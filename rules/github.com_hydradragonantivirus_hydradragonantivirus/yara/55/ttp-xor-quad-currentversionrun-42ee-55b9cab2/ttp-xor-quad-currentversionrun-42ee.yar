rule TTP_XOR_QUAD_CurrentVersionRun_42ee {
  strings:
    $key_42ee = { 11 81 [2] 35 8f [2] 1e a3 [2] 30 81 [2] 24 9a [2] 2b 80 [2] 35 9d [2] 37 9c [2] 2c 9a [2] 30 9d [2] 2c b2 }

  condition:
    any of them
}