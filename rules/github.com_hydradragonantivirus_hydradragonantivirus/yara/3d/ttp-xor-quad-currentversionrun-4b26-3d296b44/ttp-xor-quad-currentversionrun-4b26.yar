rule TTP_XOR_QUAD_CurrentVersionRun_4b26 {
  strings:
    $key_4b26 = { 18 49 [2] 3c 47 [2] 17 6b [2] 39 49 [2] 2d 52 [2] 22 48 [2] 3c 55 [2] 3e 54 [2] 25 52 [2] 39 55 [2] 25 7a }

  condition:
    any of them
}