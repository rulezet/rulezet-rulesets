rule TTP_XOR_QUAD_CurrentVersionRun_793a {
  strings:
    $key_793a = { 2a 55 [2] 0e 5b [2] 25 77 [2] 0b 55 [2] 1f 4e [2] 10 54 [2] 0e 49 [2] 0c 48 [2] 17 4e [2] 0b 49 [2] 17 66 }

  condition:
    any of them
}