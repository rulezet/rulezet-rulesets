rule TTP_XOR_QUAD_CurrentVersionRun_693a {
  strings:
    $key_693a = { 3a 55 [2] 1e 5b [2] 35 77 [2] 1b 55 [2] 0f 4e [2] 00 54 [2] 1e 49 [2] 1c 48 [2] 07 4e [2] 1b 49 [2] 07 66 }

  condition:
    any of them
}