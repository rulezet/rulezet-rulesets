rule TTP_XOR_QUAD_CurrentVersionRun_1524 {
  strings:
    $key_1524 = { 46 4b [2] 62 45 [2] 49 69 [2] 67 4b [2] 73 50 [2] 7c 4a [2] 62 57 [2] 60 56 [2] 7b 50 [2] 67 57 [2] 7b 78 }

  condition:
    any of them
}