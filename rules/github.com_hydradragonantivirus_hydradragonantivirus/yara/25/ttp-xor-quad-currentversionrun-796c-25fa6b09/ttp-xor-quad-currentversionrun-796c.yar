rule TTP_XOR_QUAD_CurrentVersionRun_796c {
  strings:
    $key_796c = { 2a 03 [2] 0e 0d [2] 25 21 [2] 0b 03 [2] 1f 18 [2] 10 02 [2] 0e 1f [2] 0c 1e [2] 17 18 [2] 0b 1f [2] 17 30 }

  condition:
    any of them
}