rule TTP_XOR_QUAD_CurrentVersionRun_1e38 {
  strings:
    $key_1e38 = { 4d 57 [2] 69 59 [2] 42 75 [2] 6c 57 [2] 78 4c [2] 77 56 [2] 69 4b [2] 6b 4a [2] 70 4c [2] 6c 4b [2] 70 64 }

  condition:
    any of them
}