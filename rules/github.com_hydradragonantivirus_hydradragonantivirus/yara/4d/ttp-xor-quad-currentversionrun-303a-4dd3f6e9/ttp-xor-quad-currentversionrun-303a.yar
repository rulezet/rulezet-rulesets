rule TTP_XOR_QUAD_CurrentVersionRun_303a {
  strings:
    $key_303a = { 63 55 [2] 47 5b [2] 6c 77 [2] 42 55 [2] 56 4e [2] 59 54 [2] 47 49 [2] 45 48 [2] 5e 4e [2] 42 49 [2] 5e 66 }

  condition:
    any of them
}