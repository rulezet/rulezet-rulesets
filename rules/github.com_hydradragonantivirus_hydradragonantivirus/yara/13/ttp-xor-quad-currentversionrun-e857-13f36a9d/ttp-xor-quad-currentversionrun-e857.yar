rule TTP_XOR_QUAD_CurrentVersionRun_e857 {
  strings:
    $key_e857 = { bb 38 [2] 9f 36 [2] b4 1a [2] 9a 38 [2] 8e 23 [2] 81 39 [2] 9f 24 [2] 9d 25 [2] 86 23 [2] 9a 24 [2] 86 0b }

  condition:
    any of them
}