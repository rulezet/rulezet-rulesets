rule TTP_XOR_QUAD_CurrentVersionRun_1915 {
  strings:
    $key_1915 = { 4a 7a [2] 6e 74 [2] 45 58 [2] 6b 7a [2] 7f 61 [2] 70 7b [2] 6e 66 [2] 6c 67 [2] 77 61 [2] 6b 66 [2] 77 49 }

  condition:
    any of them
}