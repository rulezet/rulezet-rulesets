rule TTP_XOR_QUAD_CurrentVersionRun_4214 {
  strings:
    $key_4214 = { 11 7b [2] 35 75 [2] 1e 59 [2] 30 7b [2] 24 60 [2] 2b 7a [2] 35 67 [2] 37 66 [2] 2c 60 [2] 30 67 [2] 2c 48 }

  condition:
    any of them
}