rule TTP_XOR_QUAD_CurrentVersionRun_1914 {
  strings:
    $key_1914 = { 4a 7b [2] 6e 75 [2] 45 59 [2] 6b 7b [2] 7f 60 [2] 70 7a [2] 6e 67 [2] 6c 66 [2] 77 60 [2] 6b 67 [2] 77 48 }

  condition:
    any of them
}