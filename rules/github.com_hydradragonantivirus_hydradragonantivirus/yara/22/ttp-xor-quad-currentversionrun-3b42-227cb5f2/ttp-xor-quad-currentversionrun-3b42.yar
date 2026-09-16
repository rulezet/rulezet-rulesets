rule TTP_XOR_QUAD_CurrentVersionRun_3b42 {
  strings:
    $key_3b42 = { 68 2d [2] 4c 23 [2] 67 0f [2] 49 2d [2] 5d 36 [2] 52 2c [2] 4c 31 [2] 4e 30 [2] 55 36 [2] 49 31 [2] 55 1e }

  condition:
    any of them
}