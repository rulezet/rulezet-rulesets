rule TTP_XOR_QUAD_CurrentVersionRun_1705 {
  strings:
    $key_1705 = { 44 6a [2] 60 64 [2] 4b 48 [2] 65 6a [2] 71 71 [2] 7e 6b [2] 60 76 [2] 62 77 [2] 79 71 [2] 65 76 [2] 79 59 }

  condition:
    any of them
}