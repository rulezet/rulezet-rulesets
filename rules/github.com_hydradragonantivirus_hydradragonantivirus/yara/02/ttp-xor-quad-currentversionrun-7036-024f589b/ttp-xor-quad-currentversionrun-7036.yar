rule TTP_XOR_QUAD_CurrentVersionRun_7036 {
  strings:
    $key_7036 = { 23 59 [2] 07 57 [2] 2c 7b [2] 02 59 [2] 16 42 [2] 19 58 [2] 07 45 [2] 05 44 [2] 1e 42 [2] 02 45 [2] 1e 6a }

  condition:
    any of them
}