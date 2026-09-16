rule TTP_XOR_QUAD_CurrentVersionRun_5111 {
  strings:
    $key_5111 = { 02 7e [2] 26 70 [2] 0d 5c [2] 23 7e [2] 37 65 [2] 38 7f [2] 26 62 [2] 24 63 [2] 3f 65 [2] 23 62 [2] 3f 4d }

  condition:
    any of them
}