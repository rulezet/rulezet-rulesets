rule TTP_XOR_QUAD_CurrentVersionRun_64f7 {
  strings:
    $key_64f7 = { 37 98 [2] 13 96 [2] 38 ba [2] 16 98 [2] 02 83 [2] 0d 99 [2] 13 84 [2] 11 85 [2] 0a 83 [2] 16 84 [2] 0a ab }

  condition:
    any of them
}