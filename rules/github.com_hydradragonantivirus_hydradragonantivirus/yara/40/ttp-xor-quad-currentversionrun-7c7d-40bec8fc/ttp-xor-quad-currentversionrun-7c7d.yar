rule TTP_XOR_QUAD_CurrentVersionRun_7c7d {
  strings:
    $key_7c7d = { 2f 12 [2] 0b 1c [2] 20 30 [2] 0e 12 [2] 1a 09 [2] 15 13 [2] 0b 0e [2] 09 0f [2] 12 09 [2] 0e 0e [2] 12 21 }

  condition:
    any of them
}