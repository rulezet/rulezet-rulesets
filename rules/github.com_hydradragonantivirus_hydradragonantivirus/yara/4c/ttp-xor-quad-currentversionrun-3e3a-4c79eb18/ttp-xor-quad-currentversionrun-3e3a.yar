rule TTP_XOR_QUAD_CurrentVersionRun_3e3a {
  strings:
    $key_3e3a = { 6d 55 [2] 49 5b [2] 62 77 [2] 4c 55 [2] 58 4e [2] 57 54 [2] 49 49 [2] 4b 48 [2] 50 4e [2] 4c 49 [2] 50 66 }

  condition:
    any of them
}