rule TTP_XOR_QUAD_CurrentVersionRun_eb43 {
  strings:
    $key_eb43 = { b8 2c [2] 9c 22 [2] b7 0e [2] 99 2c [2] 8d 37 [2] 82 2d [2] 9c 30 [2] 9e 31 [2] 85 37 [2] 99 30 [2] 85 1f }

  condition:
    any of them
}