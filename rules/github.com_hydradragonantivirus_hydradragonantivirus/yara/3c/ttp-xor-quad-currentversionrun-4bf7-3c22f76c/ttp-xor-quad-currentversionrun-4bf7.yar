rule TTP_XOR_QUAD_CurrentVersionRun_4bf7 {
  strings:
    $key_4bf7 = { 18 98 [2] 3c 96 [2] 17 ba [2] 39 98 [2] 2d 83 [2] 22 99 [2] 3c 84 [2] 3e 85 [2] 25 83 [2] 39 84 [2] 25 ab }

  condition:
    any of them
}