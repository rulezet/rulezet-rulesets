rule TTP_XOR_QUAD_CurrentVersionRun_411c {
  strings:
    $key_411c = { 12 73 [2] 36 7d [2] 1d 51 [2] 33 73 [2] 27 68 [2] 28 72 [2] 36 6f [2] 34 6e [2] 2f 68 [2] 33 6f [2] 2f 40 }

  condition:
    any of them
}