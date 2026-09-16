rule TTP_XOR_QUAD_CurrentVersionRun_712e {
  strings:
    $key_712e = { 22 41 [2] 06 4f [2] 2d 63 [2] 03 41 [2] 17 5a [2] 18 40 [2] 06 5d [2] 04 5c [2] 1f 5a [2] 03 5d [2] 1f 72 }

  condition:
    any of them
}