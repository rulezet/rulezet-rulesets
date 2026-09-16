rule TTP_XOR_QUAD_CurrentVersionRun_3b06 {
  strings:
    $key_3b06 = { 68 69 [2] 4c 67 [2] 67 4b [2] 49 69 [2] 5d 72 [2] 52 68 [2] 4c 75 [2] 4e 74 [2] 55 72 [2] 49 75 [2] 55 5a }

  condition:
    any of them
}