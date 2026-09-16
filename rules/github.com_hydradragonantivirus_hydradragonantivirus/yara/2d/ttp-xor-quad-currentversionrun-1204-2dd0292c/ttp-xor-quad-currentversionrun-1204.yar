rule TTP_XOR_QUAD_CurrentVersionRun_1204 {
  strings:
    $key_1204 = { 41 6b [2] 65 65 [2] 4e 49 [2] 60 6b [2] 74 70 [2] 7b 6a [2] 65 77 [2] 67 76 [2] 7c 70 [2] 60 77 [2] 7c 58 }

  condition:
    any of them
}