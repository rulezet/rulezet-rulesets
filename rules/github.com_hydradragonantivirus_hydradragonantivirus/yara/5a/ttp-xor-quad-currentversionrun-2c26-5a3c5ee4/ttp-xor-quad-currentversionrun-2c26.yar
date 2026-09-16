rule TTP_XOR_QUAD_CurrentVersionRun_2c26 {
  strings:
    $key_2c26 = { 7f 49 [2] 5b 47 [2] 70 6b [2] 5e 49 [2] 4a 52 [2] 45 48 [2] 5b 55 [2] 59 54 [2] 42 52 [2] 5e 55 [2] 42 7a }

  condition:
    any of them
}