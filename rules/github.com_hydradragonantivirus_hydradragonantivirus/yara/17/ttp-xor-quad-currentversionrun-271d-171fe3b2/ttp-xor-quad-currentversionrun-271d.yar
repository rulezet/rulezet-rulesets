rule TTP_XOR_QUAD_CurrentVersionRun_271d {
  strings:
    $key_271d = { 74 72 [2] 50 7c [2] 7b 50 [2] 55 72 [2] 41 69 [2] 4e 73 [2] 50 6e [2] 52 6f [2] 49 69 [2] 55 6e [2] 49 41 }

  condition:
    any of them
}