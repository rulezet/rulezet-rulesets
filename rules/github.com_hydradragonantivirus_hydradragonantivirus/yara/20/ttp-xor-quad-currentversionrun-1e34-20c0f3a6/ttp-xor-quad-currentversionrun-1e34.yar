rule TTP_XOR_QUAD_CurrentVersionRun_1e34 {
  strings:
    $key_1e34 = { 4d 5b [2] 69 55 [2] 42 79 [2] 6c 5b [2] 78 40 [2] 77 5a [2] 69 47 [2] 6b 46 [2] 70 40 [2] 6c 47 [2] 70 68 }

  condition:
    any of them
}