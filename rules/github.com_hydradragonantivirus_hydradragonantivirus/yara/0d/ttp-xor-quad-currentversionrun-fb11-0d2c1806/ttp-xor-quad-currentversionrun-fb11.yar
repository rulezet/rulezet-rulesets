rule TTP_XOR_QUAD_CurrentVersionRun_fb11 {
  strings:
    $key_fb11 = { a8 7e [2] 8c 70 [2] a7 5c [2] 89 7e [2] 9d 65 [2] 92 7f [2] 8c 62 [2] 8e 63 [2] 95 65 [2] 89 62 [2] 95 4d }

  condition:
    any of them
}