rule TTP_XOR_QUAD_CurrentVersionRun_1c3a {
  strings:
    $key_1c3a = { 4f 55 [2] 6b 5b [2] 40 77 [2] 6e 55 [2] 7a 4e [2] 75 54 [2] 6b 49 [2] 69 48 [2] 72 4e [2] 6e 49 [2] 72 66 }

  condition:
    any of them
}