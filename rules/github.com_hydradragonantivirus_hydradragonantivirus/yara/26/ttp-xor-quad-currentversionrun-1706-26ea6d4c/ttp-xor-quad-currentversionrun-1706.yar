rule TTP_XOR_QUAD_CurrentVersionRun_1706 {
  strings:
    $key_1706 = { 44 69 [2] 60 67 [2] 4b 4b [2] 65 69 [2] 71 72 [2] 7e 68 [2] 60 75 [2] 62 74 [2] 79 72 [2] 65 75 [2] 79 5a }

  condition:
    any of them
}