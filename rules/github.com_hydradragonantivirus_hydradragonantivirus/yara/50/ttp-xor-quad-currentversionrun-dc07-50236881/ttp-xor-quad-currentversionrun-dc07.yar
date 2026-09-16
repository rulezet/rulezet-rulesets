rule TTP_XOR_QUAD_CurrentVersionRun_dc07 {
  strings:
    $key_dc07 = { 8f 68 [2] ab 66 [2] 80 4a [2] ae 68 [2] ba 73 [2] b5 69 [2] ab 74 [2] a9 75 [2] b2 73 [2] ae 74 [2] b2 5b }

  condition:
    any of them
}