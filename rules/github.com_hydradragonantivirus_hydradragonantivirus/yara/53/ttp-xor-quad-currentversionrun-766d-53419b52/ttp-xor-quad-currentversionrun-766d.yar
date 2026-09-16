rule TTP_XOR_QUAD_CurrentVersionRun_766d {
  strings:
    $key_766d = { 25 02 [2] 01 0c [2] 2a 20 [2] 04 02 [2] 10 19 [2] 1f 03 [2] 01 1e [2] 03 1f [2] 18 19 [2] 04 1e [2] 18 31 }

  condition:
    any of them
}