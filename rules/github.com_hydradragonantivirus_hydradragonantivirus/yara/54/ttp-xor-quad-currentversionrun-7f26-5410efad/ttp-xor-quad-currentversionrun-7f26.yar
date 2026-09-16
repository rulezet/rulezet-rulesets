rule TTP_XOR_QUAD_CurrentVersionRun_7f26 {
  strings:
    $key_7f26 = { 2c 49 [2] 08 47 [2] 23 6b [2] 0d 49 [2] 19 52 [2] 16 48 [2] 08 55 [2] 0a 54 [2] 11 52 [2] 0d 55 [2] 11 7a }

  condition:
    any of them
}