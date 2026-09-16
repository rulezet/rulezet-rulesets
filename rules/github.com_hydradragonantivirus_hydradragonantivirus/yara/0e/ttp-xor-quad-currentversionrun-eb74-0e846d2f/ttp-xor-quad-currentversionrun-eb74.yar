rule TTP_XOR_QUAD_CurrentVersionRun_eb74 {
  strings:
    $key_eb74 = { b8 1b [2] 9c 15 [2] b7 39 [2] 99 1b [2] 8d 00 [2] 82 1a [2] 9c 07 [2] 9e 06 [2] 85 00 [2] 99 07 [2] 85 28 }

  condition:
    any of them
}