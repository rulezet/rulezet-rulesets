rule TTP_XOR_QUAD_CurrentVersionRun_655c {
  strings:
    $key_655c = { 36 33 [2] 12 3d [2] 39 11 [2] 17 33 [2] 03 28 [2] 0c 32 [2] 12 2f [2] 10 2e [2] 0b 28 [2] 17 2f [2] 0b 00 }

  condition:
    any of them
}