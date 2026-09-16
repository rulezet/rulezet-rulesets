rule TTP_XOR_QUAD_CurrentVersionRun_451c {
  strings:
    $key_451c = { 16 73 [2] 32 7d [2] 19 51 [2] 37 73 [2] 23 68 [2] 2c 72 [2] 32 6f [2] 30 6e [2] 2b 68 [2] 37 6f [2] 2b 40 }

  condition:
    any of them
}