rule TTP_XOR_QUAD_CurrentVersionRun_274a {
  strings:
    $key_274a = { 74 25 [2] 50 2b [2] 7b 07 [2] 55 25 [2] 41 3e [2] 4e 24 [2] 50 39 [2] 52 38 [2] 49 3e [2] 55 39 [2] 49 16 }

  condition:
    any of them
}