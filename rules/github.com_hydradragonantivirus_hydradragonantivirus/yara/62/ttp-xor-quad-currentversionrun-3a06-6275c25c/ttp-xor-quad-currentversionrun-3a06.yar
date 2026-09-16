rule TTP_XOR_QUAD_CurrentVersionRun_3a06 {
  strings:
    $key_3a06 = { 69 69 [2] 4d 67 [2] 66 4b [2] 48 69 [2] 5c 72 [2] 53 68 [2] 4d 75 [2] 4f 74 [2] 54 72 [2] 48 75 [2] 54 5a }

  condition:
    any of them
}