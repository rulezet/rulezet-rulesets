rule TTP_XOR_QUAD_CurrentVersionRun_251d {
  strings:
    $key_251d = { 76 72 [2] 52 7c [2] 79 50 [2] 57 72 [2] 43 69 [2] 4c 73 [2] 52 6e [2] 50 6f [2] 4b 69 [2] 57 6e [2] 4b 41 }

  condition:
    any of them
}