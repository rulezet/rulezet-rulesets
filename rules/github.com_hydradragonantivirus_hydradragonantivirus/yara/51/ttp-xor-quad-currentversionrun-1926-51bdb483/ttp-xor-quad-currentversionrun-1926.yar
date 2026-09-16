rule TTP_XOR_QUAD_CurrentVersionRun_1926 {
  strings:
    $key_1926 = { 4a 49 [2] 6e 47 [2] 45 6b [2] 6b 49 [2] 7f 52 [2] 70 48 [2] 6e 55 [2] 6c 54 [2] 77 52 [2] 6b 55 [2] 77 7a }

  condition:
    any of them
}