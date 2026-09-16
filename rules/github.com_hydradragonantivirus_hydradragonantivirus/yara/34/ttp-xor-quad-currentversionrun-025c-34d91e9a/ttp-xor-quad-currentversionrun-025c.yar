rule TTP_XOR_QUAD_CurrentVersionRun_025c {
  strings:
    $key_025c = { 51 33 [2] 75 3d [2] 5e 11 [2] 70 33 [2] 64 28 [2] 6b 32 [2] 75 2f [2] 77 2e [2] 6c 28 [2] 70 2f [2] 6c 00 }

  condition:
    any of them
}