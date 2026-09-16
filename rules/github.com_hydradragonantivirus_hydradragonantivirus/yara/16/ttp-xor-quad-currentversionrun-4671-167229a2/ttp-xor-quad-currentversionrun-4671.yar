rule TTP_XOR_QUAD_CurrentVersionRun_4671 {
  strings:
    $key_4671 = { 15 1e [2] 31 10 [2] 1a 3c [2] 34 1e [2] 20 05 [2] 2f 1f [2] 31 02 [2] 33 03 [2] 28 05 [2] 34 02 [2] 28 2d }

  condition:
    any of them
}