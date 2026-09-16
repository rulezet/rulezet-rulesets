rule TTP_XOR_QUAD_CurrentVersionRun_432e {
  strings:
    $key_432e = { 10 41 [2] 34 4f [2] 1f 63 [2] 31 41 [2] 25 5a [2] 2a 40 [2] 34 5d [2] 36 5c [2] 2d 5a [2] 31 5d [2] 2d 72 }

  condition:
    any of them
}