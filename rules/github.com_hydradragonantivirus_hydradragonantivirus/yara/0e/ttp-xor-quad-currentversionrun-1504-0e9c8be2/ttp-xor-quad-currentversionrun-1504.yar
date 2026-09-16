rule TTP_XOR_QUAD_CurrentVersionRun_1504 {
  strings:
    $key_1504 = { 46 6b [2] 62 65 [2] 49 49 [2] 67 6b [2] 73 70 [2] 7c 6a [2] 62 77 [2] 60 76 [2] 7b 70 [2] 67 77 [2] 7b 58 }

  condition:
    any of them
}