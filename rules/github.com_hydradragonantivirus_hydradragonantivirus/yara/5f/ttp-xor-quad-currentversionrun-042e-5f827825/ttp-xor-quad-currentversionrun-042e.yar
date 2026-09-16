rule TTP_XOR_QUAD_CurrentVersionRun_042e {
  strings:
    $key_042e = { 57 41 [2] 73 4f [2] 58 63 [2] 76 41 [2] 62 5a [2] 6d 40 [2] 73 5d [2] 71 5c [2] 6a 5a [2] 76 5d [2] 6a 72 }

  condition:
    any of them
}