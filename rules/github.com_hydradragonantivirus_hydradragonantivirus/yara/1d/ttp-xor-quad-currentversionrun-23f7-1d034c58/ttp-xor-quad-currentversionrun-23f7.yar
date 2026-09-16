rule TTP_XOR_QUAD_CurrentVersionRun_23f7 {
  strings:
    $key_23f7 = { 70 98 [2] 54 96 [2] 7f ba [2] 51 98 [2] 45 83 [2] 4a 99 [2] 54 84 [2] 56 85 [2] 4d 83 [2] 51 84 [2] 4d ab }

  condition:
    any of them
}