rule TTP_XOR_QUAD_CurrentVersionRun_3c06 {
  strings:
    $key_3c06 = { 6f 69 [2] 4b 67 [2] 60 4b [2] 4e 69 [2] 5a 72 [2] 55 68 [2] 4b 75 [2] 49 74 [2] 52 72 [2] 4e 75 [2] 52 5a }

  condition:
    any of them
}