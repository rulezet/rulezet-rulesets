rule TTP_XOR_QUAD_CurrentVersionRun_486c {
  strings:
    $key_486c = { 1b 03 [2] 3f 0d [2] 14 21 [2] 3a 03 [2] 2e 18 [2] 21 02 [2] 3f 1f [2] 3d 1e [2] 26 18 [2] 3a 1f [2] 26 30 }

  condition:
    any of them
}