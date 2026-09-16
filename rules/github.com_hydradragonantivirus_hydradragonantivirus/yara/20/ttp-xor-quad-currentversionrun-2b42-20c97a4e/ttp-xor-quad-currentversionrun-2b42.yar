rule TTP_XOR_QUAD_CurrentVersionRun_2b42 {
  strings:
    $key_2b42 = { 78 2d [2] 5c 23 [2] 77 0f [2] 59 2d [2] 4d 36 [2] 42 2c [2] 5c 31 [2] 5e 30 [2] 45 36 [2] 59 31 [2] 45 1e }

  condition:
    any of them
}