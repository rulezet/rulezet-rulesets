rule TTP_XOR_QUAD_CurrentVersionRun_0819 {
  strings:
    $key_0819 = { 5b 76 [2] 7f 78 [2] 54 54 [2] 7a 76 [2] 6e 6d [2] 61 77 [2] 7f 6a [2] 7d 6b [2] 66 6d [2] 7a 6a [2] 66 45 }

  condition:
    any of them
}