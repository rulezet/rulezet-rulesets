rule TTP_XOR_QUAD_CurrentVersionRun_103a {
  strings:
    $key_103a = { 43 55 [2] 67 5b [2] 4c 77 [2] 62 55 [2] 76 4e [2] 79 54 [2] 67 49 [2] 65 48 [2] 7e 4e [2] 62 49 [2] 7e 66 }

  condition:
    any of them
}