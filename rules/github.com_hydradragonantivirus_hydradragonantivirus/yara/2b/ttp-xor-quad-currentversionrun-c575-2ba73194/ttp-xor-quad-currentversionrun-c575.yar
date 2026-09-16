rule TTP_XOR_QUAD_CurrentVersionRun_c575 {
  strings:
    $key_c575 = { 96 1a [2] b2 14 [2] 99 38 [2] b7 1a [2] a3 01 [2] ac 1b [2] b2 06 [2] b0 07 [2] ab 01 [2] b7 06 [2] ab 29 }

  condition:
    any of them
}