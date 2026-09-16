rule TTP_XOR_QUAD_CurrentVersionRun_261e {
  strings:
    $key_261e = { 75 71 [2] 51 7f [2] 7a 53 [2] 54 71 [2] 40 6a [2] 4f 70 [2] 51 6d [2] 53 6c [2] 48 6a [2] 54 6d [2] 48 42 }

  condition:
    any of them
}