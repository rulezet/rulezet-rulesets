rule TTP_XOR_QUAD_CurrentVersionRun_192d {
  strings:
    $key_192d = { 4a 42 [2] 6e 4c [2] 45 60 [2] 6b 42 [2] 7f 59 [2] 70 43 [2] 6e 5e [2] 6c 5f [2] 77 59 [2] 6b 5e [2] 77 71 }

  condition:
    any of them
}