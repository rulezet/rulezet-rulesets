rule TTP_XOR_QUAD_CurrentVersionRun_6711 {
  strings:
    $key_6711 = { 34 7e [2] 10 70 [2] 3b 5c [2] 15 7e [2] 01 65 [2] 0e 7f [2] 10 62 [2] 12 63 [2] 09 65 [2] 15 62 [2] 09 4d }

  condition:
    any of them
}