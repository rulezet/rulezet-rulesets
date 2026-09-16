rule TTP_XOR_QUAD_CurrentVersionRun_15f7 {
  strings:
    $key_15f7 = { 46 98 [2] 62 96 [2] 49 ba [2] 67 98 [2] 73 83 [2] 7c 99 [2] 62 84 [2] 60 85 [2] 7b 83 [2] 67 84 [2] 7b ab }

  condition:
    any of them
}