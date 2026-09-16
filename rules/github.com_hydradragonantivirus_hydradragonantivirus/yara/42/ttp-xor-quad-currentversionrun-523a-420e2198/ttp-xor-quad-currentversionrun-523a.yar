rule TTP_XOR_QUAD_CurrentVersionRun_523a {
  strings:
    $key_523a = { 01 55 [2] 25 5b [2] 0e 77 [2] 20 55 [2] 34 4e [2] 3b 54 [2] 25 49 [2] 27 48 [2] 3c 4e [2] 20 49 [2] 3c 66 }

  condition:
    any of them
}