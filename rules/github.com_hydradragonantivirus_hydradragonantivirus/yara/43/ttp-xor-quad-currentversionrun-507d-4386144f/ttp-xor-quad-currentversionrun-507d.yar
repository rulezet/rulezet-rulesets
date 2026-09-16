rule TTP_XOR_QUAD_CurrentVersionRun_507d {
  strings:
    $key_507d = { 03 12 [2] 27 1c [2] 0c 30 [2] 22 12 [2] 36 09 [2] 39 13 [2] 27 0e [2] 25 0f [2] 3e 09 [2] 22 0e [2] 3e 21 }

  condition:
    any of them
}