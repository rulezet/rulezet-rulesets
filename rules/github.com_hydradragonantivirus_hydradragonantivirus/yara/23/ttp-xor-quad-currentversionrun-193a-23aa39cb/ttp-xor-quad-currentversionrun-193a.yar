rule TTP_XOR_QUAD_CurrentVersionRun_193a {
  strings:
    $key_193a = { 4a 55 [2] 6e 5b [2] 45 77 [2] 6b 55 [2] 7f 4e [2] 70 54 [2] 6e 49 [2] 6c 48 [2] 77 4e [2] 6b 49 [2] 77 66 }

  condition:
    any of them
}