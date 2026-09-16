rule TTP_XOR_QUAD_CurrentVersionRun_2c02 {
  strings:
    $key_2c02 = { 7f 6d [2] 5b 63 [2] 70 4f [2] 5e 6d [2] 4a 76 [2] 45 6c [2] 5b 71 [2] 59 70 [2] 42 76 [2] 5e 71 [2] 42 5e }

  condition:
    any of them
}