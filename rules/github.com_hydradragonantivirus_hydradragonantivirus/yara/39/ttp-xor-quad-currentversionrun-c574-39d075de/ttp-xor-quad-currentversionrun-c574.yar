rule TTP_XOR_QUAD_CurrentVersionRun_c574 {
  strings:
    $key_c574 = { 96 1b [2] b2 15 [2] 99 39 [2] b7 1b [2] a3 00 [2] ac 1a [2] b2 07 [2] b0 06 [2] ab 00 [2] b7 07 [2] ab 28 }

  condition:
    any of them
}