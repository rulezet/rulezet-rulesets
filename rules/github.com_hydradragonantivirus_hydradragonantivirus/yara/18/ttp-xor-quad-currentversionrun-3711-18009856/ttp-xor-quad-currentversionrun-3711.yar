rule TTP_XOR_QUAD_CurrentVersionRun_3711 {
  strings:
    $key_3711 = { 64 7e [2] 40 70 [2] 6b 5c [2] 45 7e [2] 51 65 [2] 5e 7f [2] 40 62 [2] 42 63 [2] 59 65 [2] 45 62 [2] 59 4d }

  condition:
    any of them
}