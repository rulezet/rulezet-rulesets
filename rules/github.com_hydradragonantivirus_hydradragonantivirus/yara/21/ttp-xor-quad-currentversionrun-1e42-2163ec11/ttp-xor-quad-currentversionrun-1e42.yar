rule TTP_XOR_QUAD_CurrentVersionRun_1e42 {
  strings:
    $key_1e42 = { 4d 2d [2] 69 23 [2] 42 0f [2] 6c 2d [2] 78 36 [2] 77 2c [2] 69 31 [2] 6b 30 [2] 70 36 [2] 6c 31 [2] 70 1e }

  condition:
    any of them
}