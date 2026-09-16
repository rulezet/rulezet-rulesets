rule TTP_XOR_QUAD_CurrentVersionRun_1919 {
  strings:
    $key_1919 = { 4a 76 [2] 6e 78 [2] 45 54 [2] 6b 76 [2] 7f 6d [2] 70 77 [2] 6e 6a [2] 6c 6b [2] 77 6d [2] 6b 6a [2] 77 45 }

  condition:
    any of them
}