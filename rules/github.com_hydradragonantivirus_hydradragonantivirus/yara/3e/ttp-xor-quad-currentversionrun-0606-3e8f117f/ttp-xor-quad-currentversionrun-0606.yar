rule TTP_XOR_QUAD_CurrentVersionRun_0606 {
  strings:
    $key_0606 = { 55 69 [2] 71 67 [2] 5a 4b [2] 74 69 [2] 60 72 [2] 6f 68 [2] 71 75 [2] 73 74 [2] 68 72 [2] 74 75 [2] 68 5a }

  condition:
    any of them
}