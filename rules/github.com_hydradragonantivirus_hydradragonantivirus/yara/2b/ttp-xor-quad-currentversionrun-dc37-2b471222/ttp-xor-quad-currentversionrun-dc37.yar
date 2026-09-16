rule TTP_XOR_QUAD_CurrentVersionRun_dc37 {
  strings:
    $key_dc37 = { 8f 58 [2] ab 56 [2] 80 7a [2] ae 58 [2] ba 43 [2] b5 59 [2] ab 44 [2] a9 45 [2] b2 43 [2] ae 44 [2] b2 6b }

  condition:
    any of them
}