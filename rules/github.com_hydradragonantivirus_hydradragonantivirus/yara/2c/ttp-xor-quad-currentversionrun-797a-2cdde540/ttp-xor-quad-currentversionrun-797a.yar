rule TTP_XOR_QUAD_CurrentVersionRun_797a {
  strings:
    $key_797a = { 2a 15 [2] 0e 1b [2] 25 37 [2] 0b 15 [2] 1f 0e [2] 10 14 [2] 0e 09 [2] 0c 08 [2] 17 0e [2] 0b 09 [2] 17 26 }

  condition:
    any of them
}