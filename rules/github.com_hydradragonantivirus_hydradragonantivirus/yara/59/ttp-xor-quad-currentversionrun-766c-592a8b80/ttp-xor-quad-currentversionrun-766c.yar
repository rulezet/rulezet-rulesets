rule TTP_XOR_QUAD_CurrentVersionRun_766c {
  strings:
    $key_766c = { 25 03 [2] 01 0d [2] 2a 21 [2] 04 03 [2] 10 18 [2] 1f 02 [2] 01 1f [2] 03 1e [2] 18 18 [2] 04 1f [2] 18 30 }

  condition:
    any of them
}