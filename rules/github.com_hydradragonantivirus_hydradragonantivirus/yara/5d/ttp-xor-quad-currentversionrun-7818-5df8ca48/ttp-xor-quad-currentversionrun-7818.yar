rule TTP_XOR_QUAD_CurrentVersionRun_7818 {
  strings:
    $key_7818 = { 2b 77 [2] 0f 79 [2] 24 55 [2] 0a 77 [2] 1e 6c [2] 11 76 [2] 0f 6b [2] 0d 6a [2] 16 6c [2] 0a 6b [2] 16 44 }

  condition:
    any of them
}