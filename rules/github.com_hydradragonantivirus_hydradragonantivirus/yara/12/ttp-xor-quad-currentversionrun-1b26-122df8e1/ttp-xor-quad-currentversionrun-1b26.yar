rule TTP_XOR_QUAD_CurrentVersionRun_1b26 {
  strings:
    $key_1b26 = { 48 49 [2] 6c 47 [2] 47 6b [2] 69 49 [2] 7d 52 [2] 72 48 [2] 6c 55 [2] 6e 54 [2] 75 52 [2] 69 55 [2] 75 7a }

  condition:
    any of them
}