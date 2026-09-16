rule TTP_XOR_QUAD_CurrentVersionRun_171b {
  strings:
    $key_171b = { 44 74 [2] 60 7a [2] 4b 56 [2] 65 74 [2] 71 6f [2] 7e 75 [2] 60 68 [2] 62 69 [2] 79 6f [2] 65 68 [2] 79 47 }

  condition:
    any of them
}