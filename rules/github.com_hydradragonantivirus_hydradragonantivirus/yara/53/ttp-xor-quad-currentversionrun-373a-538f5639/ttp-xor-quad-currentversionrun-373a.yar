rule TTP_XOR_QUAD_CurrentVersionRun_373a {
  strings:
    $key_373a = { 64 55 [2] 40 5b [2] 6b 77 [2] 45 55 [2] 51 4e [2] 5e 54 [2] 40 49 [2] 42 48 [2] 59 4e [2] 45 49 [2] 59 66 }

  condition:
    any of them
}