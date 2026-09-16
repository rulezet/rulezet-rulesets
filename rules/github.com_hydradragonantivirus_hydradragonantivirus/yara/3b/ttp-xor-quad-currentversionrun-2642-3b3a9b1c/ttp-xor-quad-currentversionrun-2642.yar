rule TTP_XOR_QUAD_CurrentVersionRun_2642 {
  strings:
    $key_2642 = { 75 2d [2] 51 23 [2] 7a 0f [2] 54 2d [2] 40 36 [2] 4f 2c [2] 51 31 [2] 53 30 [2] 48 36 [2] 54 31 [2] 48 1e }

  condition:
    any of them
}