rule TTP_XOR_QUAD_CurrentVersionRun_eb67 {
  strings:
    $key_eb67 = { b8 08 [2] 9c 06 [2] b7 2a [2] 99 08 [2] 8d 13 [2] 82 09 [2] 9c 14 [2] 9e 15 [2] 85 13 [2] 99 14 [2] 85 3b }

  condition:
    any of them
}