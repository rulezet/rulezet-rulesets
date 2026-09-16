rule TTP_XOR_QUAD_CurrentVersionRun_323a {
  strings:
    $key_323a = { 61 55 [2] 45 5b [2] 6e 77 [2] 40 55 [2] 54 4e [2] 5b 54 [2] 45 49 [2] 47 48 [2] 5c 4e [2] 40 49 [2] 5c 66 }

  condition:
    any of them
}