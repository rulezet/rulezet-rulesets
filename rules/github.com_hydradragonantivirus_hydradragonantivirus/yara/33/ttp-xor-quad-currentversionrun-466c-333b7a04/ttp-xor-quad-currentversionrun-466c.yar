rule TTP_XOR_QUAD_CurrentVersionRun_466c {
  strings:
    $key_466c = { 15 03 [2] 31 0d [2] 1a 21 [2] 34 03 [2] 20 18 [2] 2f 02 [2] 31 1f [2] 33 1e [2] 28 18 [2] 34 1f [2] 28 30 }

  condition:
    any of them
}