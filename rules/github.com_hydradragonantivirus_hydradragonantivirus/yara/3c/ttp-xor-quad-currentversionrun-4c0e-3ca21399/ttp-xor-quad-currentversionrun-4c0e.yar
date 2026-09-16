rule TTP_XOR_QUAD_CurrentVersionRun_4c0e {
  strings:
    $key_4c0e = { 1f 61 [2] 3b 6f [2] 10 43 [2] 3e 61 [2] 2a 7a [2] 25 60 [2] 3b 7d [2] 39 7c [2] 22 7a [2] 3e 7d [2] 22 52 }

  condition:
    any of them
}