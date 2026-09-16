rule TTP_XOR_QUAD_CurrentVersionRun_0042 {
  strings:
    $key_0042 = { 53 2d [2] 77 23 [2] 5c 0f [2] 72 2d [2] 66 36 [2] 69 2c [2] 77 31 [2] 75 30 [2] 6e 36 [2] 72 31 [2] 6e 1e }

  condition:
    any of them
}