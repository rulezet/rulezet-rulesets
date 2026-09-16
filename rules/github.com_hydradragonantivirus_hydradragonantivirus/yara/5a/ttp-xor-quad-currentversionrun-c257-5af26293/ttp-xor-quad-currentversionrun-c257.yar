rule TTP_XOR_QUAD_CurrentVersionRun_c257 {
  strings:
    $key_c257 = { 91 38 [2] b5 36 [2] 9e 1a [2] b0 38 [2] a4 23 [2] ab 39 [2] b5 24 [2] b7 25 [2] ac 23 [2] b0 24 [2] ac 0b }

  condition:
    any of them
}