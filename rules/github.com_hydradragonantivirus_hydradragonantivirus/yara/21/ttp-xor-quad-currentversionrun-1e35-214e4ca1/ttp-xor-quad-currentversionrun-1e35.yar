rule TTP_XOR_QUAD_CurrentVersionRun_1e35 {
  strings:
    $key_1e35 = { 4d 5a [2] 69 54 [2] 42 78 [2] 6c 5a [2] 78 41 [2] 77 5b [2] 69 46 [2] 6b 47 [2] 70 41 [2] 6c 46 [2] 70 69 }

  condition:
    any of them
}