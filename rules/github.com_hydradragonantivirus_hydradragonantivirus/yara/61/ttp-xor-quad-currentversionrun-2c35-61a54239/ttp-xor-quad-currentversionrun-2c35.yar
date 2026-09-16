rule TTP_XOR_QUAD_CurrentVersionRun_2c35 {
  strings:
    $key_2c35 = { 7f 5a [2] 5b 54 [2] 70 78 [2] 5e 5a [2] 4a 41 [2] 45 5b [2] 5b 46 [2] 59 47 [2] 42 41 [2] 5e 46 [2] 42 69 }

  condition:
    any of them
}