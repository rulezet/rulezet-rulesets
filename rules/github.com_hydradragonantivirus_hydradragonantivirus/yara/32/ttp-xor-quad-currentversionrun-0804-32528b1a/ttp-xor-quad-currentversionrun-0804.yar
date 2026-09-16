rule TTP_XOR_QUAD_CurrentVersionRun_0804 {
  strings:
    $key_0804 = { 5b 6b [2] 7f 65 [2] 54 49 [2] 7a 6b [2] 6e 70 [2] 61 6a [2] 7f 77 [2] 7d 76 [2] 66 70 [2] 7a 77 [2] 66 58 }

  condition:
    any of them
}