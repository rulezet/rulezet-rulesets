rule TTP_XOR_QUAD_CurrentVersionRun_eb47 {
  strings:
    $key_eb47 = { b8 28 [2] 9c 26 [2] b7 0a [2] 99 28 [2] 8d 33 [2] 82 29 [2] 9c 34 [2] 9e 35 [2] 85 33 [2] 99 34 [2] 85 1b }

  condition:
    any of them
}