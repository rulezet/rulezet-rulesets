rule TTP_XOR_QUAD_CurrentVersionRun_eb71 {
  strings:
    $key_eb71 = { b8 1e [2] 9c 10 [2] b7 3c [2] 99 1e [2] 8d 05 [2] 82 1f [2] 9c 02 [2] 9e 03 [2] 85 05 [2] 99 02 [2] 85 2d }

  condition:
    any of them
}