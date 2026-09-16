rule TTP_XOR_QUAD_CurrentVersionRun_1519 {
  strings:
    $key_1519 = { 46 76 [2] 62 78 [2] 49 54 [2] 67 76 [2] 73 6d [2] 7c 77 [2] 62 6a [2] 60 6b [2] 7b 6d [2] 67 6a [2] 7b 45 }

  condition:
    any of them
}