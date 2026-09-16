rule TTP_XOR_QUAD_CurrentVersionRun_eb57 {
  strings:
    $key_eb57 = { b8 38 [2] 9c 36 [2] b7 1a [2] 99 38 [2] 8d 23 [2] 82 39 [2] 9c 24 [2] 9e 25 [2] 85 23 [2] 99 24 [2] 85 0b }

  condition:
    any of them
}