rule TTP_XOR_QUAD_CurrentVersionRun_1b06 {
  strings:
    $key_1b06 = { 48 69 [2] 6c 67 [2] 47 4b [2] 69 69 [2] 7d 72 [2] 72 68 [2] 6c 75 [2] 6e 74 [2] 75 72 [2] 69 75 [2] 75 5a }

  condition:
    any of them
}