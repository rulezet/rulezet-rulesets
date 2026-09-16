rule TTP_XOR_QUAD_CurrentVersionRun_5036 {
  strings:
    $key_5036 = { 03 59 [2] 27 57 [2] 0c 7b [2] 22 59 [2] 36 42 [2] 39 58 [2] 27 45 [2] 25 44 [2] 3e 42 [2] 22 45 [2] 3e 6a }

  condition:
    any of them
}