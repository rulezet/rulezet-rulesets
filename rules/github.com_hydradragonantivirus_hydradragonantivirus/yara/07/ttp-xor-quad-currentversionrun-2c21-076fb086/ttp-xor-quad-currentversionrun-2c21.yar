rule TTP_XOR_QUAD_CurrentVersionRun_2c21 {
  strings:
    $key_2c21 = { 7f 4e [2] 5b 40 [2] 70 6c [2] 5e 4e [2] 4a 55 [2] 45 4f [2] 5b 52 [2] 59 53 [2] 42 55 [2] 5e 52 [2] 42 7d }

  condition:
    any of them
}