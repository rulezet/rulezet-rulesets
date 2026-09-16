rule TTP_XOR_QUAD_CurrentVersionRun_1316 {
  strings:
    $key_1316 = { 40 79 [2] 64 77 [2] 4f 5b [2] 61 79 [2] 75 62 [2] 7a 78 [2] 64 65 [2] 66 64 [2] 7d 62 [2] 61 65 [2] 7d 4a }

  condition:
    any of them
}