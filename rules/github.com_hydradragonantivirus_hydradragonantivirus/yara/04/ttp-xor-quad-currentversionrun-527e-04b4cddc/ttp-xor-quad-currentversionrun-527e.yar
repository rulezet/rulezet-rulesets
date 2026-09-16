rule TTP_XOR_QUAD_CurrentVersionRun_527e {
  strings:
    $key_527e = { 01 11 [2] 25 1f [2] 0e 33 [2] 20 11 [2] 34 0a [2] 3b 10 [2] 25 0d [2] 27 0c [2] 3c 0a [2] 20 0d [2] 3c 22 }

  condition:
    any of them
}