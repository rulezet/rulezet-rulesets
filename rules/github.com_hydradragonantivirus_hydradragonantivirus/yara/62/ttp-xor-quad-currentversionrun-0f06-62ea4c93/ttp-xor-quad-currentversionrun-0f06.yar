rule TTP_XOR_QUAD_CurrentVersionRun_0f06 {
  strings:
    $key_0f06 = { 5c 69 [2] 78 67 [2] 53 4b [2] 7d 69 [2] 69 72 [2] 66 68 [2] 78 75 [2] 7a 74 [2] 61 72 [2] 7d 75 [2] 61 5a }

  condition:
    any of them
}