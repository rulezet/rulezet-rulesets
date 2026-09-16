rule TTP_XOR_QUAD_CurrentVersionRun_1724 {
  strings:
    $key_1724 = { 44 4b [2] 60 45 [2] 4b 69 [2] 65 4b [2] 71 50 [2] 7e 4a [2] 60 57 [2] 62 56 [2] 79 50 [2] 65 57 [2] 79 78 }

  condition:
    any of them
}