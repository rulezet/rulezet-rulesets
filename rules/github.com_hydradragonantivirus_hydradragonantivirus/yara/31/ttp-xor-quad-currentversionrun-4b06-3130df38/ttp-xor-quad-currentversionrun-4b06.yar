rule TTP_XOR_QUAD_CurrentVersionRun_4b06 {
  strings:
    $key_4b06 = { 18 69 [2] 3c 67 [2] 17 4b [2] 39 69 [2] 2d 72 [2] 22 68 [2] 3c 75 [2] 3e 74 [2] 25 72 [2] 39 75 [2] 25 5a }

  condition:
    any of them
}