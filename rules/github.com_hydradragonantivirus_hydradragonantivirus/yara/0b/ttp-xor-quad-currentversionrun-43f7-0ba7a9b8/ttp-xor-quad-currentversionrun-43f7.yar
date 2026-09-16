rule TTP_XOR_QUAD_CurrentVersionRun_43f7 {
  strings:
    $key_43f7 = { 10 98 [2] 34 96 [2] 1f ba [2] 31 98 [2] 25 83 [2] 2a 99 [2] 34 84 [2] 36 85 [2] 2d 83 [2] 31 84 [2] 2d ab }

  condition:
    any of them
}