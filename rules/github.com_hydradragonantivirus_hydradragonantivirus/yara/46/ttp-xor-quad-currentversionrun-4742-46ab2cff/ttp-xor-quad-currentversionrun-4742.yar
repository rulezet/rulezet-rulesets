rule TTP_XOR_QUAD_CurrentVersionRun_4742 {
  strings:
    $key_4742 = { 14 2d [2] 30 23 [2] 1b 0f [2] 35 2d [2] 21 36 [2] 2e 2c [2] 30 31 [2] 32 30 [2] 29 36 [2] 35 31 [2] 29 1e }

  condition:
    any of them
}