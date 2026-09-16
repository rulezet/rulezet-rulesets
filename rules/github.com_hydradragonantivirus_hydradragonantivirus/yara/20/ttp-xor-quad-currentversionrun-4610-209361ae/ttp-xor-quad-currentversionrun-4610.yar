rule TTP_XOR_QUAD_CurrentVersionRun_4610 {
  strings:
    $key_4610 = { 15 7f [2] 31 71 [2] 1a 5d [2] 34 7f [2] 20 64 [2] 2f 7e [2] 31 63 [2] 33 62 [2] 28 64 [2] 34 63 [2] 28 4c }

  condition:
    any of them
}