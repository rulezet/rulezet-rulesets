rule TTP_XOR_QUAD_CurrentVersionRun_3504 {
  strings:
    $key_3504 = { 66 6b [2] 42 65 [2] 69 49 [2] 47 6b [2] 53 70 [2] 5c 6a [2] 42 77 [2] 40 76 [2] 5b 70 [2] 47 77 [2] 5b 58 }

  condition:
    any of them
}