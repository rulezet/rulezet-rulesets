rule TTP_XOR_QUAD_CurrentVersionRun_0806 {
  strings:
    $key_0806 = { 5b 69 [2] 7f 67 [2] 54 4b [2] 7a 69 [2] 6e 72 [2] 61 68 [2] 7f 75 [2] 7d 74 [2] 66 72 [2] 7a 75 [2] 66 5a }

  condition:
    any of them
}