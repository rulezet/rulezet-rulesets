rule TTP_XOR_QUAD_CurrentVersionRun_6a06 {
  strings:
    $key_6a06 = { 39 69 [2] 1d 67 [2] 36 4b [2] 18 69 [2] 0c 72 [2] 03 68 [2] 1d 75 [2] 1f 74 [2] 04 72 [2] 18 75 [2] 04 5a }

  condition:
    any of them
}