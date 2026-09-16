rule TTP_XOR_QUAD_CurrentVersionRun_087e {
  strings:
    $key_087e = { 5b 11 [2] 7f 1f [2] 54 33 [2] 7a 11 [2] 6e 0a [2] 61 10 [2] 7f 0d [2] 7d 0c [2] 66 0a [2] 7a 0d [2] 66 22 }

  condition:
    any of them
}