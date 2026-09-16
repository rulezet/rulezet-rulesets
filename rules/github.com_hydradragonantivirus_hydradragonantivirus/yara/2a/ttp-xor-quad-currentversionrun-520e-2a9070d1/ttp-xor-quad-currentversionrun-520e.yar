rule TTP_XOR_QUAD_CurrentVersionRun_520e {
  strings:
    $key_520e = { 01 61 [2] 25 6f [2] 0e 43 [2] 20 61 [2] 34 7a [2] 3b 60 [2] 25 7d [2] 27 7c [2] 3c 7a [2] 20 7d [2] 3c 52 }

  condition:
    any of them
}