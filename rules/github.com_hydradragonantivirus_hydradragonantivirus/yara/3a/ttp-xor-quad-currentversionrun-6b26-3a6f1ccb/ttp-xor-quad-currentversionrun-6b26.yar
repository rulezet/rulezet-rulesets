rule TTP_XOR_QUAD_CurrentVersionRun_6b26 {
  strings:
    $key_6b26 = { 38 49 [2] 1c 47 [2] 37 6b [2] 19 49 [2] 0d 52 [2] 02 48 [2] 1c 55 [2] 1e 54 [2] 05 52 [2] 19 55 [2] 05 7a }

  condition:
    any of them
}