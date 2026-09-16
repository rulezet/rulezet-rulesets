rule TTP_XOR_QUAD_CurrentVersionRun_dc25 {
  strings:
    $key_dc25 = { 8f 4a [2] ab 44 [2] 80 68 [2] ae 4a [2] ba 51 [2] b5 4b [2] ab 56 [2] a9 57 [2] b2 51 [2] ae 56 [2] b2 79 }

  condition:
    any of them
}