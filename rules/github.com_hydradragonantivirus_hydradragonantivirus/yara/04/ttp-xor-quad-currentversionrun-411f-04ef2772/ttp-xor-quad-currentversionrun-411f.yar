rule TTP_XOR_QUAD_CurrentVersionRun_411f {
  strings:
    $key_411f = { 12 70 [2] 36 7e [2] 1d 52 [2] 33 70 [2] 27 6b [2] 28 71 [2] 36 6c [2] 34 6d [2] 2f 6b [2] 33 6c [2] 2f 43 }

  condition:
    any of them
}