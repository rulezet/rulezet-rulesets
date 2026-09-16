rule TTP_XOR_QUAD_CurrentVersionRun_74f7 {
  strings:
    $key_74f7 = { 27 98 [2] 03 96 [2] 28 ba [2] 06 98 [2] 12 83 [2] 1d 99 [2] 03 84 [2] 01 85 [2] 1a 83 [2] 06 84 [2] 1a ab }

  condition:
    any of them
}