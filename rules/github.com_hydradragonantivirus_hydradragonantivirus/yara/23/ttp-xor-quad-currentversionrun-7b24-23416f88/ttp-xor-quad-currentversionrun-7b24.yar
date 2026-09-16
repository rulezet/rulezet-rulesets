rule TTP_XOR_QUAD_CurrentVersionRun_7b24 {
  strings:
    $key_7b24 = { 28 4b [2] 0c 45 [2] 27 69 [2] 09 4b [2] 1d 50 [2] 12 4a [2] 0c 57 [2] 0e 56 [2] 15 50 [2] 09 57 [2] 15 78 }

  condition:
    any of them
}