rule TTP_XOR_QUAD_CurrentVersionRun_1764 {
  strings:
    $key_1764 = { 44 0b [2] 60 05 [2] 4b 29 [2] 65 0b [2] 71 10 [2] 7e 0a [2] 60 17 [2] 62 16 [2] 79 10 [2] 65 17 [2] 79 38 }

  condition:
    any of them
}