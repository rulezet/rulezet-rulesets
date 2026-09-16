rule TTP_XOR_QUAD_CurrentVersionRun_5f51 {
  strings:
    $key_5f51 = { 0c 3e [2] 28 30 [2] 03 1c [2] 2d 3e [2] 39 25 [2] 36 3f [2] 28 22 [2] 2a 23 [2] 31 25 [2] 2d 22 [2] 31 0d }

  condition:
    any of them
}