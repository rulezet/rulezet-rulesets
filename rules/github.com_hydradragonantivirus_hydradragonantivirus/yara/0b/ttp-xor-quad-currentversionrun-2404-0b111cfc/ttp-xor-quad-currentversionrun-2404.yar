rule TTP_XOR_QUAD_CurrentVersionRun_2404 {
  strings:
    $key_2404 = { 77 6b [2] 53 65 [2] 78 49 [2] 56 6b [2] 42 70 [2] 4d 6a [2] 53 77 [2] 51 76 [2] 4a 70 [2] 56 77 [2] 4a 58 }

  condition:
    any of them
}