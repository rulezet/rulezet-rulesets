rule TTP_XOR_QUAD_CurrentVersionRun_313a {
  strings:
    $key_313a = { 62 55 [2] 46 5b [2] 6d 77 [2] 43 55 [2] 57 4e [2] 58 54 [2] 46 49 [2] 44 48 [2] 5f 4e [2] 43 49 [2] 5f 66 }

  condition:
    any of them
}