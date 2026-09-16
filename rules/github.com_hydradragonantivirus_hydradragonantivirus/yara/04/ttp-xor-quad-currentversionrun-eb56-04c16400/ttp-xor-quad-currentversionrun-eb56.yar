rule TTP_XOR_QUAD_CurrentVersionRun_eb56 {
  strings:
    $key_eb56 = { b8 39 [2] 9c 37 [2] b7 1b [2] 99 39 [2] 8d 22 [2] 82 38 [2] 9c 25 [2] 9e 24 [2] 85 22 [2] 99 25 [2] 85 0a }

  condition:
    any of them
}