rule TTP_XOR_QUAD_CurrentVersionRun_3e24 {
  strings:
    $key_3e24 = { 6d 4b [2] 49 45 [2] 62 69 [2] 4c 4b [2] 58 50 [2] 57 4a [2] 49 57 [2] 4b 56 [2] 50 50 [2] 4c 57 [2] 50 78 }

  condition:
    any of them
}