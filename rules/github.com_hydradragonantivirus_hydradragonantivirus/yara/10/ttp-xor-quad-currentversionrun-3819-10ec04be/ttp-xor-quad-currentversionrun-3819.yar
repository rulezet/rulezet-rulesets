rule TTP_XOR_QUAD_CurrentVersionRun_3819 {
  strings:
    $key_3819 = { 6b 76 [2] 4f 78 [2] 64 54 [2] 4a 76 [2] 5e 6d [2] 51 77 [2] 4f 6a [2] 4d 6b [2] 56 6d [2] 4a 6a [2] 56 45 }

  condition:
    any of them
}