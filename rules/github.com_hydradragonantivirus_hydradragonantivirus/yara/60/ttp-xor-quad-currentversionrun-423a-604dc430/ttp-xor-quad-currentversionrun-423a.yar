rule TTP_XOR_QUAD_CurrentVersionRun_423a {
  strings:
    $key_423a = { 11 55 [2] 35 5b [2] 1e 77 [2] 30 55 [2] 24 4e [2] 2b 54 [2] 35 49 [2] 37 48 [2] 2c 4e [2] 30 49 [2] 2c 66 }

  condition:
    any of them
}