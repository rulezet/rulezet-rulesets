rule TTP_XOR_QUAD_CurrentVersionRun_1f16 {
  strings:
    $key_1f16 = { 4c 79 [2] 68 77 [2] 43 5b [2] 6d 79 [2] 79 62 [2] 76 78 [2] 68 65 [2] 6a 64 [2] 71 62 [2] 6d 65 [2] 71 4a }

  condition:
    any of them
}