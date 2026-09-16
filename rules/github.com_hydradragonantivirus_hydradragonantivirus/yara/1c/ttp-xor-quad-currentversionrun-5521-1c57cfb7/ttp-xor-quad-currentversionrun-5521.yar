rule TTP_XOR_QUAD_CurrentVersionRun_5521 {
  strings:
    $key_5521 = { 06 4e [2] 22 40 [2] 09 6c [2] 27 4e [2] 33 55 [2] 3c 4f [2] 22 52 [2] 20 53 [2] 3b 55 [2] 27 52 [2] 3b 7d }

  condition:
    any of them
}