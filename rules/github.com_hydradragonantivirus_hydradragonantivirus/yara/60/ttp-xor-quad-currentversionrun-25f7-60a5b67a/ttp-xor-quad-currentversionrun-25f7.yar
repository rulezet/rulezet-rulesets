rule TTP_XOR_QUAD_CurrentVersionRun_25f7 {
  strings:
    $key_25f7 = { 76 98 [2] 52 96 [2] 79 ba [2] 57 98 [2] 43 83 [2] 4c 99 [2] 52 84 [2] 50 85 [2] 4b 83 [2] 57 84 [2] 4b ab }

  condition:
    any of them
}