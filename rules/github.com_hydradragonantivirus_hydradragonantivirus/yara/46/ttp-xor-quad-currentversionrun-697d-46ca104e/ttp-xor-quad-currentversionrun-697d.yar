rule TTP_XOR_QUAD_CurrentVersionRun_697d {
  strings:
    $key_697d = { 3a 12 [2] 1e 1c [2] 35 30 [2] 1b 12 [2] 0f 09 [2] 00 13 [2] 1e 0e [2] 1c 0f [2] 07 09 [2] 1b 0e [2] 07 21 }

  condition:
    any of them
}