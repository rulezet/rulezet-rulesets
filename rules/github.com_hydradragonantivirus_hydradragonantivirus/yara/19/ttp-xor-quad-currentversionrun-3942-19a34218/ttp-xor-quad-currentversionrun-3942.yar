rule TTP_XOR_QUAD_CurrentVersionRun_3942 {
  strings:
    $key_3942 = { 6a 2d [2] 4e 23 [2] 65 0f [2] 4b 2d [2] 5f 36 [2] 50 2c [2] 4e 31 [2] 4c 30 [2] 57 36 [2] 4b 31 [2] 57 1e }

  condition:
    any of them
}