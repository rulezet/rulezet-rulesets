rule TTP_XOR_QUAD_CurrentVersionRun_797d {
  strings:
    $key_797d = { 2a 12 [2] 0e 1c [2] 25 30 [2] 0b 12 [2] 1f 09 [2] 10 13 [2] 0e 0e [2] 0c 0f [2] 17 09 [2] 0b 0e [2] 17 21 }

  condition:
    any of them
}