rule TTP_XOR_QUAD_CurrentVersionRun_7e11 {
  strings:
    $key_7e11 = { 2d 7e [2] 09 70 [2] 22 5c [2] 0c 7e [2] 18 65 [2] 17 7f [2] 09 62 [2] 0b 63 [2] 10 65 [2] 0c 62 [2] 10 4d }

  condition:
    any of them
}