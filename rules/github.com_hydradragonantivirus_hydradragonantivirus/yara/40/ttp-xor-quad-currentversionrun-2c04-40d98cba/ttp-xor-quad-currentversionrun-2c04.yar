rule TTP_XOR_QUAD_CurrentVersionRun_2c04 {
  strings:
    $key_2c04 = { 7f 6b [2] 5b 65 [2] 70 49 [2] 5e 6b [2] 4a 70 [2] 45 6a [2] 5b 77 [2] 59 76 [2] 42 70 [2] 5e 77 [2] 42 58 }

  condition:
    any of them
}