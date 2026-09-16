rule TTP_XOR_QUAD_CurrentVersionRun_093a {
  strings:
    $key_093a = { 5a 55 [2] 7e 5b [2] 55 77 [2] 7b 55 [2] 6f 4e [2] 60 54 [2] 7e 49 [2] 7c 48 [2] 67 4e [2] 7b 49 [2] 67 66 }

  condition:
    any of them
}