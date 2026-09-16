rule TTP_XOR_QUAD_CurrentVersionRun_262e {
  strings:
    $key_262e = { 75 41 [2] 51 4f [2] 7a 63 [2] 54 41 [2] 40 5a [2] 4f 40 [2] 51 5d [2] 53 5c [2] 48 5a [2] 54 5d [2] 48 72 }

  condition:
    any of them
}