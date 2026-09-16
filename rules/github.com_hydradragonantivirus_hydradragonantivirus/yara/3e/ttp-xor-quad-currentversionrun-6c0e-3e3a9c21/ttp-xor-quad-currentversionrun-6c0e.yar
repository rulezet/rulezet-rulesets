rule TTP_XOR_QUAD_CurrentVersionRun_6c0e {
  strings:
    $key_6c0e = { 3f 61 [2] 1b 6f [2] 30 43 [2] 1e 61 [2] 0a 7a [2] 05 60 [2] 1b 7d [2] 19 7c [2] 02 7a [2] 1e 7d [2] 02 52 }

  condition:
    any of them
}