rule TTP_XOR_QUAD_CurrentVersionRun_1526 {
  strings:
    $key_1526 = { 46 49 [2] 62 47 [2] 49 6b [2] 67 49 [2] 73 52 [2] 7c 48 [2] 62 55 [2] 60 54 [2] 7b 52 [2] 67 55 [2] 7b 7a }

  condition:
    any of them
}