rule TTP_XOR_QUAD_CurrentVersionRun_4604 {
  strings:
    $key_4604 = { 15 6b [2] 31 65 [2] 1a 49 [2] 34 6b [2] 20 70 [2] 2f 6a [2] 31 77 [2] 33 76 [2] 28 70 [2] 34 77 [2] 28 58 }

  condition:
    any of them
}