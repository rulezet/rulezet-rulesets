rule TTP_XOR_QUAD_CurrentVersionRun_765c {
  strings:
    $key_765c = { 25 33 [2] 01 3d [2] 2a 11 [2] 04 33 [2] 10 28 [2] 1f 32 [2] 01 2f [2] 03 2e [2] 18 28 [2] 04 2f [2] 18 00 }

  condition:
    any of them
}