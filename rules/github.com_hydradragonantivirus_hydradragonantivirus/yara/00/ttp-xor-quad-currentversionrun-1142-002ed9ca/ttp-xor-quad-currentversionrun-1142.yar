rule TTP_XOR_QUAD_CurrentVersionRun_1142 {
  strings:
    $key_1142 = { 42 2d [2] 66 23 [2] 4d 0f [2] 63 2d [2] 77 36 [2] 78 2c [2] 66 31 [2] 64 30 [2] 7f 36 [2] 63 31 [2] 7f 1e }

  condition:
    any of them
}