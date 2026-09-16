rule TTP_XOR_QUAD_CurrentVersionRun_5506 {
  strings:
    $key_5506 = { 06 69 [2] 22 67 [2] 09 4b [2] 27 69 [2] 33 72 [2] 3c 68 [2] 22 75 [2] 20 74 [2] 3b 72 [2] 27 75 [2] 3b 5a }

  condition:
    any of them
}