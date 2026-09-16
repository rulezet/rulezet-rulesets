rule TTP_XOR_QUAD_CurrentVersionRun_1766 {
  strings:
    $key_1766 = { 44 09 [2] 60 07 [2] 4b 2b [2] 65 09 [2] 71 12 [2] 7e 08 [2] 60 15 [2] 62 14 [2] 79 12 [2] 65 15 [2] 79 3a }

  condition:
    any of them
}