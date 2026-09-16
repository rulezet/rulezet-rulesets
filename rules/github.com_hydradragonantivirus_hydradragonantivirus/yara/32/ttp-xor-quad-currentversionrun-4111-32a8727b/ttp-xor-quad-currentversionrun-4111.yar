rule TTP_XOR_QUAD_CurrentVersionRun_4111 {
  strings:
    $key_4111 = { 12 7e [2] 36 70 [2] 1d 5c [2] 33 7e [2] 27 65 [2] 28 7f [2] 36 62 [2] 34 63 [2] 2f 65 [2] 33 62 [2] 2f 4d }

  condition:
    any of them
}