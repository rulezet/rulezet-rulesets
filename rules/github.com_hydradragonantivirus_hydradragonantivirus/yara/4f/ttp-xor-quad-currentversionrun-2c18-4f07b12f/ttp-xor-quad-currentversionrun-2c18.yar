rule TTP_XOR_QUAD_CurrentVersionRun_2c18 {
  strings:
    $key_2c18 = { 7f 77 [2] 5b 79 [2] 70 55 [2] 5e 77 [2] 4a 6c [2] 45 76 [2] 5b 6b [2] 59 6a [2] 42 6c [2] 5e 6b [2] 42 44 }

  condition:
    any of them
}