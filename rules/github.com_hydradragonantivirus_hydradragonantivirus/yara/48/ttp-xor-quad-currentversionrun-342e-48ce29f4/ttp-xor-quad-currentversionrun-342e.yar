rule TTP_XOR_QUAD_CurrentVersionRun_342e {
  strings:
    $key_342e = { 67 41 [2] 43 4f [2] 68 63 [2] 46 41 [2] 52 5a [2] 5d 40 [2] 43 5d [2] 41 5c [2] 5a 5a [2] 46 5d [2] 5a 72 }

  condition:
    any of them
}