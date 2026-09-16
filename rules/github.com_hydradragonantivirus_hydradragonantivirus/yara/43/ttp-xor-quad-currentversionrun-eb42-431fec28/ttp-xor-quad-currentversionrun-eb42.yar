rule TTP_XOR_QUAD_CurrentVersionRun_eb42 {
  strings:
    $key_eb42 = { b8 2d [2] 9c 23 [2] b7 0f [2] 99 2d [2] 8d 36 [2] 82 2c [2] 9c 31 [2] 9e 30 [2] 85 36 [2] 99 31 [2] 85 1e }

  condition:
    any of them
}