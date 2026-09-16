rule TTP_XOR_QUAD_CurrentVersionRun_3242 {
  strings:
    $key_3242 = { 61 2d [2] 45 23 [2] 6e 0f [2] 40 2d [2] 54 36 [2] 5b 2c [2] 45 31 [2] 47 30 [2] 5c 36 [2] 40 31 [2] 5c 1e }

  condition:
    any of them
}