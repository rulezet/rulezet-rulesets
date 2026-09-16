rule TTP_XOR_QUAD_CurrentVersionRun_5006 {
  strings:
    $key_5006 = { 03 69 [2] 27 67 [2] 0c 4b [2] 22 69 [2] 36 72 [2] 39 68 [2] 27 75 [2] 25 74 [2] 3e 72 [2] 22 75 [2] 3e 5a }

  condition:
    any of them
}