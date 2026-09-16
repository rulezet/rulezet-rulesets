rule TTP_XOR_QUAD_CurrentVersionRun_7718 {
  strings:
    $key_7718 = { 24 77 [2] 00 79 [2] 2b 55 [2] 05 77 [2] 11 6c [2] 1e 76 [2] 00 6b [2] 02 6a [2] 19 6c [2] 05 6b [2] 19 44 }

  condition:
    any of them
}