rule TTP_XOR_QUAD_CurrentVersionRun_450c {
  strings:
    $key_450c = { 16 63 [2] 32 6d [2] 19 41 [2] 37 63 [2] 23 78 [2] 2c 62 [2] 32 7f [2] 30 7e [2] 2b 78 [2] 37 7f [2] 2b 50 }

  condition:
    any of them
}