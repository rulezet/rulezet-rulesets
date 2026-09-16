rule TTP_XOR_QUAD_CurrentVersionRun_656d {
  strings:
    $key_656d = { 36 02 [2] 12 0c [2] 39 20 [2] 17 02 [2] 03 19 [2] 0c 03 [2] 12 1e [2] 10 1f [2] 0b 19 [2] 17 1e [2] 0b 31 }

  condition:
    any of them
}