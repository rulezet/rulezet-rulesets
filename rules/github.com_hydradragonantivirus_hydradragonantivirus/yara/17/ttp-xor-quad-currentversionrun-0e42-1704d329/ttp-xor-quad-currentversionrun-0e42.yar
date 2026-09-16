rule TTP_XOR_QUAD_CurrentVersionRun_0e42 {
  strings:
    $key_0e42 = { 5d 2d [2] 79 23 [2] 52 0f [2] 7c 2d [2] 68 36 [2] 67 2c [2] 79 31 [2] 7b 30 [2] 60 36 [2] 7c 31 [2] 60 1e }

  condition:
    any of them
}