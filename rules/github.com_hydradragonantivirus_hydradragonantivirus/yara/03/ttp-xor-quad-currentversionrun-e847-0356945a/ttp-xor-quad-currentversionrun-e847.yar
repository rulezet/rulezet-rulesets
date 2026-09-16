rule TTP_XOR_QUAD_CurrentVersionRun_e847 {
  strings:
    $key_e847 = { bb 28 [2] 9f 26 [2] b4 0a [2] 9a 28 [2] 8e 33 [2] 81 29 [2] 9f 34 [2] 9d 35 [2] 86 33 [2] 9a 34 [2] 86 1b }

  condition:
    any of them
}