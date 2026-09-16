rule TTP_XOR_QUAD_CurrentVersionRun_3525 {
  strings:
    $key_3525 = { 66 4a [2] 42 44 [2] 69 68 [2] 47 4a [2] 53 51 [2] 5c 4b [2] 42 56 [2] 40 57 [2] 5b 51 [2] 47 56 [2] 5b 79 }

  condition:
    any of them
}