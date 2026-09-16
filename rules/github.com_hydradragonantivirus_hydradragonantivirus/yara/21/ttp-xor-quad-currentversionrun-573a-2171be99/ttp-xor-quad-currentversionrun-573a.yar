rule TTP_XOR_QUAD_CurrentVersionRun_573a {
  strings:
    $key_573a = { 04 55 [2] 20 5b [2] 0b 77 [2] 25 55 [2] 31 4e [2] 3e 54 [2] 20 49 [2] 22 48 [2] 39 4e [2] 25 49 [2] 39 66 }

  condition:
    any of them
}