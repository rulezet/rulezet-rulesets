rule TTP_XOR_QUAD_CurrentVersionRun_68f7 {
  strings:
    $key_68f7 = { 3b 98 [2] 1f 96 [2] 34 ba [2] 1a 98 [2] 0e 83 [2] 01 99 [2] 1f 84 [2] 1d 85 [2] 06 83 [2] 1a 84 [2] 06 ab }

  condition:
    any of them
}