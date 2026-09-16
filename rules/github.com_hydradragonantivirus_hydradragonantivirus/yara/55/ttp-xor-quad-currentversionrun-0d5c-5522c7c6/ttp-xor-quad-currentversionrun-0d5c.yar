rule TTP_XOR_QUAD_CurrentVersionRun_0d5c {
  strings:
    $key_0d5c = { 5e 33 [2] 7a 3d [2] 51 11 [2] 7f 33 [2] 6b 28 [2] 64 32 [2] 7a 2f [2] 78 2e [2] 63 28 [2] 7f 2f [2] 63 00 }

  condition:
    any of them
}