rule TTP_XOR_QUAD_CurrentVersionRun_dc5b {
  strings:
    $key_dc5b = { 8f 34 [2] ab 3a [2] 80 16 [2] ae 34 [2] ba 2f [2] b5 35 [2] ab 28 [2] a9 29 [2] b2 2f [2] ae 28 [2] b2 07 }

  condition:
    any of them
}