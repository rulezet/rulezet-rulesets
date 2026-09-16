rule TTP_XOR_QUAD_CurrentVersionRun_4e11 {
  strings:
    $key_4e11 = { 1d 7e [2] 39 70 [2] 12 5c [2] 3c 7e [2] 28 65 [2] 27 7f [2] 39 62 [2] 3b 63 [2] 20 65 [2] 3c 62 [2] 20 4d }

  condition:
    any of them
}