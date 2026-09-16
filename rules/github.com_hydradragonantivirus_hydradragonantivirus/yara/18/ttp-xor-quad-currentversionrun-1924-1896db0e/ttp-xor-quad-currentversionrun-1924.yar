rule TTP_XOR_QUAD_CurrentVersionRun_1924 {
  strings:
    $key_1924 = { 4a 4b [2] 6e 45 [2] 45 69 [2] 6b 4b [2] 7f 50 [2] 70 4a [2] 6e 57 [2] 6c 56 [2] 77 50 [2] 6b 57 [2] 77 78 }

  condition:
    any of them
}