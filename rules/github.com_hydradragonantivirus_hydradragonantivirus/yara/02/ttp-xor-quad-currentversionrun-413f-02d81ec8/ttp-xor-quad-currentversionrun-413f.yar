rule TTP_XOR_QUAD_CurrentVersionRun_413f {
  strings:
    $key_413f = { 12 50 [2] 36 5e [2] 1d 72 [2] 33 50 [2] 27 4b [2] 28 51 [2] 36 4c [2] 34 4d [2] 2f 4b [2] 33 4c [2] 2f 63 }

  condition:
    any of them
}