rule TTP_XOR_QUAD_CurrentVersionRun_796d {
  strings:
    $key_796d = { 2a 02 [2] 0e 0c [2] 25 20 [2] 0b 02 [2] 1f 19 [2] 10 03 [2] 0e 1e [2] 0c 1f [2] 17 19 [2] 0b 1e [2] 17 31 }

  condition:
    any of them
}