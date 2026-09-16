rule TTP_XOR_QUAD_CurrentVersionRun_7a7d {
  strings:
    $key_7a7d = { 29 12 [2] 0d 1c [2] 26 30 [2] 08 12 [2] 1c 09 [2] 13 13 [2] 0d 0e [2] 0f 0f [2] 14 09 [2] 08 0e [2] 14 21 }

  condition:
    any of them
}