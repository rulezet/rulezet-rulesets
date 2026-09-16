rule TTP_XOR_QUAD_CurrentVersionRun_183a {
  strings:
    $key_183a = { 4b 55 [2] 6f 5b [2] 44 77 [2] 6a 55 [2] 7e 4e [2] 71 54 [2] 6f 49 [2] 6d 48 [2] 76 4e [2] 6a 49 [2] 76 66 }

  condition:
    any of them
}