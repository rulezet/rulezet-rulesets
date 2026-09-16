rule TTP_XOR_QUAD_CurrentVersionRun_1216 {
  strings:
    $key_1216 = { 41 79 [2] 65 77 [2] 4e 5b [2] 60 79 [2] 74 62 [2] 7b 78 [2] 65 65 [2] 67 64 [2] 7c 62 [2] 60 65 [2] 7c 4a }

  condition:
    any of them
}