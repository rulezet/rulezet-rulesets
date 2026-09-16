rule TTP_XOR_QUAD_CurrentVersionRun_5226 {
  strings:
    $key_5226 = { 01 49 [2] 25 47 [2] 0e 6b [2] 20 49 [2] 34 52 [2] 3b 48 [2] 25 55 [2] 27 54 [2] 3c 52 [2] 20 55 [2] 3c 7a }

  condition:
    any of them
}