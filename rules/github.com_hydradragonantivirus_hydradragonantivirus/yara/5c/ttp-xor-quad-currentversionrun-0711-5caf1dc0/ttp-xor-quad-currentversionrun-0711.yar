rule TTP_XOR_QUAD_CurrentVersionRun_0711 {
  strings:
    $key_0711 = { 54 7e [2] 70 70 [2] 5b 5c [2] 75 7e [2] 61 65 [2] 6e 7f [2] 70 62 [2] 72 63 [2] 69 65 [2] 75 62 [2] 69 4d }

  condition:
    any of them
}