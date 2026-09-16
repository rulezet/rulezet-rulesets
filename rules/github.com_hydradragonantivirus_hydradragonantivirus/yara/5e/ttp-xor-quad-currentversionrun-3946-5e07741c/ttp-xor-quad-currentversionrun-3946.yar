rule TTP_XOR_QUAD_CurrentVersionRun_3946 {
  strings:
    $key_3946 = { 6a 29 [2] 4e 27 [2] 65 0b [2] 4b 29 [2] 5f 32 [2] 50 28 [2] 4e 35 [2] 4c 34 [2] 57 32 [2] 4b 35 [2] 57 1a }

  condition:
    any of them
}