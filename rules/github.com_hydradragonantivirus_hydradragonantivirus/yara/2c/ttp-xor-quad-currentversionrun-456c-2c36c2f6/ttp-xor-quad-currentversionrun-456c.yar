rule TTP_XOR_QUAD_CurrentVersionRun_456c {
  strings:
    $key_456c = { 16 03 [2] 32 0d [2] 19 21 [2] 37 03 [2] 23 18 [2] 2c 02 [2] 32 1f [2] 30 1e [2] 2b 18 [2] 37 1f [2] 2b 30 }

  condition:
    any of them
}