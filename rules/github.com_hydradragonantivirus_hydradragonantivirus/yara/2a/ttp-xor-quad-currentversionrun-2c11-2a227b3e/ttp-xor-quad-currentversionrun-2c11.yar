rule TTP_XOR_QUAD_CurrentVersionRun_2c11 {
  strings:
    $key_2c11 = { 7f 7e [2] 5b 70 [2] 70 5c [2] 5e 7e [2] 4a 65 [2] 45 7f [2] 5b 62 [2] 59 63 [2] 42 65 [2] 5e 62 [2] 42 4d }

  condition:
    any of them
}