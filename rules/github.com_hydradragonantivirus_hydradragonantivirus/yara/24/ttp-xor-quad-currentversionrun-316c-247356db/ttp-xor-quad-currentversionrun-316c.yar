rule TTP_XOR_QUAD_CurrentVersionRun_316c {
  strings:
    $key_316c = { 62 03 [2] 46 0d [2] 6d 21 [2] 43 03 [2] 57 18 [2] 58 02 [2] 46 1f [2] 44 1e [2] 5f 18 [2] 43 1f [2] 5f 30 }

  condition:
    any of them
}