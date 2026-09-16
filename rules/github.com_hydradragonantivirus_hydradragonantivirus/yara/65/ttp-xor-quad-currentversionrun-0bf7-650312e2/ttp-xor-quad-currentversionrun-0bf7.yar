rule TTP_XOR_QUAD_CurrentVersionRun_0bf7 {
  strings:
    $key_0bf7 = { 58 98 [2] 7c 96 [2] 57 ba [2] 79 98 [2] 6d 83 [2] 62 99 [2] 7c 84 [2] 7e 85 [2] 65 83 [2] 79 84 [2] 65 ab }

  condition:
    any of them
}