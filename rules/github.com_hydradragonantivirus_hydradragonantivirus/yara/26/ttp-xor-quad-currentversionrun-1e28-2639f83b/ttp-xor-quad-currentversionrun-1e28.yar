rule TTP_XOR_QUAD_CurrentVersionRun_1e28 {
  strings:
    $key_1e28 = { 4d 47 [2] 69 49 [2] 42 65 [2] 6c 47 [2] 78 5c [2] 77 46 [2] 69 5b [2] 6b 5a [2] 70 5c [2] 6c 5b [2] 70 74 }

  condition:
    any of them
}