rule TTP_XOR_QUAD_CurrentVersionRun_277c {
  strings:
    $key_277c = { 74 13 [2] 50 1d [2] 7b 31 [2] 55 13 [2] 41 08 [2] 4e 12 [2] 50 0f [2] 52 0e [2] 49 08 [2] 55 0f [2] 49 20 }

  condition:
    any of them
}