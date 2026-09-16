rule TTP_XOR_QUAD_CurrentVersionRun_4c26 {
  strings:
    $key_4c26 = { 1f 49 [2] 3b 47 [2] 10 6b [2] 3e 49 [2] 2a 52 [2] 25 48 [2] 3b 55 [2] 39 54 [2] 22 52 [2] 3e 55 [2] 22 7a }

  condition:
    any of them
}