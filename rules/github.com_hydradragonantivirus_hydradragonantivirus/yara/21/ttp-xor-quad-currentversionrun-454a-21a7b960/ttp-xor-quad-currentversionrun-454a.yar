rule TTP_XOR_QUAD_CurrentVersionRun_454a {
  strings:
    $key_454a = { 16 25 [2] 32 2b [2] 19 07 [2] 37 25 [2] 23 3e [2] 2c 24 [2] 32 39 [2] 30 38 [2] 2b 3e [2] 37 39 [2] 2b 16 }

  condition:
    any of them
}