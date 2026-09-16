rule TTP_XOR_QUAD_CurrentVersionRun_2c14 {
  strings:
    $key_2c14 = { 7f 7b [2] 5b 75 [2] 70 59 [2] 5e 7b [2] 4a 60 [2] 45 7a [2] 5b 67 [2] 59 66 [2] 42 60 [2] 5e 67 [2] 42 48 }

  condition:
    any of them
}