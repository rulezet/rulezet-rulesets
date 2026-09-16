rule TTP_XOR_QUAD_CurrentVersionRun_2711 {
  strings:
    $key_2711 = { 74 7e [2] 50 70 [2] 7b 5c [2] 55 7e [2] 41 65 [2] 4e 7f [2] 50 62 [2] 52 63 [2] 49 65 [2] 55 62 [2] 49 4d }

  condition:
    any of them
}