rule TTP_XOR_QUAD_CurrentVersionRun_1905 {
  strings:
    $key_1905 = { 4a 6a [2] 6e 64 [2] 45 48 [2] 6b 6a [2] 7f 71 [2] 70 6b [2] 6e 76 [2] 6c 77 [2] 77 71 [2] 6b 76 [2] 77 59 }

  condition:
    any of them
}