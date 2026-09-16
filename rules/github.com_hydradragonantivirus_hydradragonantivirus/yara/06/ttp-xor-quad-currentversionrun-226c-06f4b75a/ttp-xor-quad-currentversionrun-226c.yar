rule TTP_XOR_QUAD_CurrentVersionRun_226c {
  strings:
    $key_226c = { 71 03 [2] 55 0d [2] 7e 21 [2] 50 03 [2] 44 18 [2] 4b 02 [2] 55 1f [2] 57 1e [2] 4c 18 [2] 50 1f [2] 4c 30 }

  condition:
    any of them
}