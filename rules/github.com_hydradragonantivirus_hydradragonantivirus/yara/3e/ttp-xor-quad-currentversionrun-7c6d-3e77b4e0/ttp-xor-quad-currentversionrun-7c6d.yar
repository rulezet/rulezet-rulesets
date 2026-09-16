rule TTP_XOR_QUAD_CurrentVersionRun_7c6d {
  strings:
    $key_7c6d = { 2f 02 [2] 0b 0c [2] 20 20 [2] 0e 02 [2] 1a 19 [2] 15 03 [2] 0b 1e [2] 09 1f [2] 12 19 [2] 0e 1e [2] 12 31 }

  condition:
    any of them
}