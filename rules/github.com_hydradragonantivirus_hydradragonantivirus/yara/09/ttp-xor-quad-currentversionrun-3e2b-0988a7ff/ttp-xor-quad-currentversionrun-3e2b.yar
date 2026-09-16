rule TTP_XOR_QUAD_CurrentVersionRun_3e2b {
  strings:
    $key_3e2b = { 6d 44 [2] 49 4a [2] 62 66 [2] 4c 44 [2] 58 5f [2] 57 45 [2] 49 58 [2] 4b 59 [2] 50 5f [2] 4c 58 [2] 50 77 }

  condition:
    any of them
}