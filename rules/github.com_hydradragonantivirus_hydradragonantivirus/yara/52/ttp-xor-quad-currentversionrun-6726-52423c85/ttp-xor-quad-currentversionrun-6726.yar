rule TTP_XOR_QUAD_CurrentVersionRun_6726 {
  strings:
    $key_6726 = { 34 49 [2] 10 47 [2] 3b 6b [2] 15 49 [2] 01 52 [2] 0e 48 [2] 10 55 [2] 12 54 [2] 09 52 [2] 15 55 [2] 09 7a }

  condition:
    any of them
}