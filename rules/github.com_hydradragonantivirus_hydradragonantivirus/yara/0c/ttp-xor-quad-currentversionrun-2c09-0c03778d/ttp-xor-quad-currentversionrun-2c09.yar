rule TTP_XOR_QUAD_CurrentVersionRun_2c09 {
  strings:
    $key_2c09 = { 7f 66 [2] 5b 68 [2] 70 44 [2] 5e 66 [2] 4a 7d [2] 45 67 [2] 5b 7a [2] 59 7b [2] 42 7d [2] 5e 7a [2] 42 55 }

  condition:
    any of them
}