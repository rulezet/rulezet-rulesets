rule TTP_XOR_QUAD_CurrentVersionRun_c567 {
  strings:
    $key_c567 = { 96 08 [2] b2 06 [2] 99 2a [2] b7 08 [2] a3 13 [2] ac 09 [2] b2 14 [2] b0 15 [2] ab 13 [2] b7 14 [2] ab 3b }

  condition:
    any of them
}