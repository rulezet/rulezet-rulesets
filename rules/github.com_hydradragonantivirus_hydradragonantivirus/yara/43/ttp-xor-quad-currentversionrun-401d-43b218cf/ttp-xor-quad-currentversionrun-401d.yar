rule TTP_XOR_QUAD_CurrentVersionRun_401d {
  strings:
    $key_401d = { 13 72 [2] 37 7c [2] 1c 50 [2] 32 72 [2] 26 69 [2] 29 73 [2] 37 6e [2] 35 6f [2] 2e 69 [2] 32 6e [2] 2e 41 }

  condition:
    any of them
}