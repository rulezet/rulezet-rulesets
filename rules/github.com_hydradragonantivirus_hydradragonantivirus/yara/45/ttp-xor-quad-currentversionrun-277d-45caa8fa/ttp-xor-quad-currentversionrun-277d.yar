rule TTP_XOR_QUAD_CurrentVersionRun_277d {
  strings:
    $key_277d = { 74 12 [2] 50 1c [2] 7b 30 [2] 55 12 [2] 41 09 [2] 4e 13 [2] 50 0e [2] 52 0f [2] 49 09 [2] 55 0e [2] 49 21 }

  condition:
    any of them
}