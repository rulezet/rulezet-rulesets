rule TTP_XOR_QUAD_CurrentVersionRun_5511 {
  strings:
    $key_5511 = { 06 7e [2] 22 70 [2] 09 5c [2] 27 7e [2] 33 65 [2] 3c 7f [2] 22 62 [2] 20 63 [2] 3b 65 [2] 27 62 [2] 3b 4d }

  condition:
    any of them
}