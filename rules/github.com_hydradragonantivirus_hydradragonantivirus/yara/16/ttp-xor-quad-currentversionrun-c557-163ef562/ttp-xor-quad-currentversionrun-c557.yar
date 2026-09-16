rule TTP_XOR_QUAD_CurrentVersionRun_c557 {
  strings:
    $key_c557 = { 96 38 [2] b2 36 [2] 99 1a [2] b7 38 [2] a3 23 [2] ac 39 [2] b2 24 [2] b0 25 [2] ab 23 [2] b7 24 [2] ab 0b }

  condition:
    any of them
}