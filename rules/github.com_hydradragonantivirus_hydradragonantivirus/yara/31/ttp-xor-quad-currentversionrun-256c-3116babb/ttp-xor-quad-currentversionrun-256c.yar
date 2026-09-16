rule TTP_XOR_QUAD_CurrentVersionRun_256c {
  strings:
    $key_256c = { 76 03 [2] 52 0d [2] 79 21 [2] 57 03 [2] 43 18 [2] 4c 02 [2] 52 1f [2] 50 1e [2] 4b 18 [2] 57 1f [2] 4b 30 }

  condition:
    any of them
}