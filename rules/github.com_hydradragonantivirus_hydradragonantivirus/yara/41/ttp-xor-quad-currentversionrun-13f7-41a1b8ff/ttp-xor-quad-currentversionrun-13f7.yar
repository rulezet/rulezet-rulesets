rule TTP_XOR_QUAD_CurrentVersionRun_13f7 {
  strings:
    $key_13f7 = { 40 98 [2] 64 96 [2] 4f ba [2] 61 98 [2] 75 83 [2] 7a 99 [2] 64 84 [2] 66 85 [2] 7d 83 [2] 61 84 [2] 7d ab }

  condition:
    any of them
}