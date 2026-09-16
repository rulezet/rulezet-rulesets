rule TTP_XOR_QUAD_CurrentVersionRun_2b26 {
  strings:
    $key_2b26 = { 78 49 [2] 5c 47 [2] 77 6b [2] 59 49 [2] 4d 52 [2] 42 48 [2] 5c 55 [2] 5e 54 [2] 45 52 [2] 59 55 [2] 45 7a }

  condition:
    any of them
}