rule TTP_XOR_QUAD_CurrentVersionRun_2c08 {
  strings:
    $key_2c08 = { 7f 67 [2] 5b 69 [2] 70 45 [2] 5e 67 [2] 4a 7c [2] 45 66 [2] 5b 7b [2] 59 7a [2] 42 7c [2] 5e 7b [2] 42 54 }

  condition:
    any of them
}