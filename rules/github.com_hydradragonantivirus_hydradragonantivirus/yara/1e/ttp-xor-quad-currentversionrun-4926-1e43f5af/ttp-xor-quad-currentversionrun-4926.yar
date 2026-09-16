rule TTP_XOR_QUAD_CurrentVersionRun_4926 {
  strings:
    $key_4926 = { 1a 49 [2] 3e 47 [2] 15 6b [2] 3b 49 [2] 2f 52 [2] 20 48 [2] 3e 55 [2] 3c 54 [2] 27 52 [2] 3b 55 [2] 27 7a }

  condition:
    any of them
}