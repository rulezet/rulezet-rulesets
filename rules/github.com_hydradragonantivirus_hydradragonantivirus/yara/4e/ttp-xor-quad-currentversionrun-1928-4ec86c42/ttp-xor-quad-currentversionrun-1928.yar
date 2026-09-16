rule TTP_XOR_QUAD_CurrentVersionRun_1928 {
  strings:
    $key_1928 = { 4a 47 [2] 6e 49 [2] 45 65 [2] 6b 47 [2] 7f 5c [2] 70 46 [2] 6e 5b [2] 6c 5a [2] 77 5c [2] 6b 5b [2] 77 74 }

  condition:
    any of them
}