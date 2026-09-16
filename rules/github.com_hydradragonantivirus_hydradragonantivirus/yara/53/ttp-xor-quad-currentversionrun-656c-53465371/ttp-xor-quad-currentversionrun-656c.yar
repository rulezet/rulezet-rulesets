rule TTP_XOR_QUAD_CurrentVersionRun_656c {
  strings:
    $key_656c = { 36 03 [2] 12 0d [2] 39 21 [2] 17 03 [2] 03 18 [2] 0c 02 [2] 12 1f [2] 10 1e [2] 0b 18 [2] 17 1f [2] 0b 30 }

  condition:
    any of them
}