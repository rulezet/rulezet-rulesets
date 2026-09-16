rule TTP_XOR_QUAD_CurrentVersionRun_1024 {
  strings:
    $key_1024 = { 43 4b [2] 67 45 [2] 4c 69 [2] 62 4b [2] 76 50 [2] 79 4a [2] 67 57 [2] 65 56 [2] 7e 50 [2] 62 57 [2] 7e 78 }

  condition:
    any of them
}