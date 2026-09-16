rule TTP_XOR_QUAD_CurrentVersionRun_6f26 {
  strings:
    $key_6f26 = { 3c 49 [2] 18 47 [2] 33 6b [2] 1d 49 [2] 09 52 [2] 06 48 [2] 18 55 [2] 1a 54 [2] 01 52 [2] 1d 55 [2] 01 7a }

  condition:
    any of them
}