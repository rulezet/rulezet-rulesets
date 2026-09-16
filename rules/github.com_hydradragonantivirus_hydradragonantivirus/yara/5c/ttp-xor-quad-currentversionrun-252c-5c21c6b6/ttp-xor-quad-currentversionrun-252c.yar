rule TTP_XOR_QUAD_CurrentVersionRun_252c {
  strings:
    $key_252c = { 76 43 [2] 52 4d [2] 79 61 [2] 57 43 [2] 43 58 [2] 4c 42 [2] 52 5f [2] 50 5e [2] 4b 58 [2] 57 5f [2] 4b 70 }

  condition:
    any of them
}