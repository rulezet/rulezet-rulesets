rule TTP_XOR_QUAD_CurrentVersionRun_6b06 {
  strings:
    $key_6b06 = { 38 69 [2] 1c 67 [2] 37 4b [2] 19 69 [2] 0d 72 [2] 02 68 [2] 1c 75 [2] 1e 74 [2] 05 72 [2] 19 75 [2] 05 5a }

  condition:
    any of them
}