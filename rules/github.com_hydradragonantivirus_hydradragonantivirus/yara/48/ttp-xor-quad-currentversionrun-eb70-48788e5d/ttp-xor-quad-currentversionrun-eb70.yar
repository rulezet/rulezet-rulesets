rule TTP_XOR_QUAD_CurrentVersionRun_eb70 {
  strings:
    $key_eb70 = { b8 1f [2] 9c 11 [2] b7 3d [2] 99 1f [2] 8d 04 [2] 82 1e [2] 9c 03 [2] 9e 02 [2] 85 04 [2] 99 03 [2] 85 2c }

  condition:
    any of them
}