rule TTP_XOR_QUAD_CurrentVersionRun_dc39 {
  strings:
    $key_dc39 = { 8f 56 [2] ab 58 [2] 80 74 [2] ae 56 [2] ba 4d [2] b5 57 [2] ab 4a [2] a9 4b [2] b2 4d [2] ae 4a [2] b2 65 }

  condition:
    any of them
}