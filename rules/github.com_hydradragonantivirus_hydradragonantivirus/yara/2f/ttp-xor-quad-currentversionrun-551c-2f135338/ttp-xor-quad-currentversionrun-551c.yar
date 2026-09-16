rule TTP_XOR_QUAD_CurrentVersionRun_551c {
  strings:
    $key_551c = { 06 73 [2] 22 7d [2] 09 51 [2] 27 73 [2] 33 68 [2] 3c 72 [2] 22 6f [2] 20 6e [2] 3b 68 [2] 27 6f [2] 3b 40 }

  condition:
    any of them
}