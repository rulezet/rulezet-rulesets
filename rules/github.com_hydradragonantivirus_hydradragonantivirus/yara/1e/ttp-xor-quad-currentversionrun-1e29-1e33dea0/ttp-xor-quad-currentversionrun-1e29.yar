rule TTP_XOR_QUAD_CurrentVersionRun_1e29 {
  strings:
    $key_1e29 = { 4d 46 [2] 69 48 [2] 42 64 [2] 6c 46 [2] 78 5d [2] 77 47 [2] 69 5a [2] 6b 5b [2] 70 5d [2] 6c 5a [2] 70 75 }

  condition:
    any of them
}