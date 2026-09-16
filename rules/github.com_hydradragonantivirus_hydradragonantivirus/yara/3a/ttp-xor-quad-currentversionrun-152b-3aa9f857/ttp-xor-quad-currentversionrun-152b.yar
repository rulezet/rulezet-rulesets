rule TTP_XOR_QUAD_CurrentVersionRun_152b {
  strings:
    $key_152b = { 46 44 [2] 62 4a [2] 49 66 [2] 67 44 [2] 73 5f [2] 7c 45 [2] 62 58 [2] 60 59 [2] 7b 5f [2] 67 58 [2] 7b 77 }

  condition:
    any of them
}