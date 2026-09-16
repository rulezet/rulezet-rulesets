rule TTP_XOR_QUAD_CurrentVersionRun_42eb {
  strings:
    $key_42eb = { 11 84 [2] 35 8a [2] 1e a6 [2] 30 84 [2] 24 9f [2] 2b 85 [2] 35 98 [2] 37 99 [2] 2c 9f [2] 30 98 [2] 2c b7 }

  condition:
    any of them
}