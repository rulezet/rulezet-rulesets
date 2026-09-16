rule TTP_XOR_QUAD_CurrentVersionRun_dc74 {
  strings:
    $key_dc74 = { 8f 1b [2] ab 15 [2] 80 39 [2] ae 1b [2] ba 00 [2] b5 1a [2] ab 07 [2] a9 06 [2] b2 00 [2] ae 07 [2] b2 28 }

  condition:
    any of them
}