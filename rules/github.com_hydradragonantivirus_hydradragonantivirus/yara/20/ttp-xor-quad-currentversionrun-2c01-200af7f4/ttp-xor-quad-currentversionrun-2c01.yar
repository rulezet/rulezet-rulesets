rule TTP_XOR_QUAD_CurrentVersionRun_2c01 {
  strings:
    $key_2c01 = { 7f 6e [2] 5b 60 [2] 70 4c [2] 5e 6e [2] 4a 75 [2] 45 6f [2] 5b 72 [2] 59 73 [2] 42 75 [2] 5e 72 [2] 42 5d }

  condition:
    any of them
}