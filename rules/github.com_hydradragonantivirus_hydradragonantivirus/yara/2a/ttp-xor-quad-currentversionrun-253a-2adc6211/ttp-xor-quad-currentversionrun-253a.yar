rule TTP_XOR_QUAD_CurrentVersionRun_253a {
  strings:
    $key_253a = { 76 55 [2] 52 5b [2] 79 77 [2] 57 55 [2] 43 4e [2] 4c 54 [2] 52 49 [2] 50 48 [2] 4b 4e [2] 57 49 [2] 4b 66 }

  condition:
    any of them
}