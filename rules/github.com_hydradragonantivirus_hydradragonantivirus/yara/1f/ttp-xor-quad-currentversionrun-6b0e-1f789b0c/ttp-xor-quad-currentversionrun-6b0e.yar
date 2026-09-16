rule TTP_XOR_QUAD_CurrentVersionRun_6b0e {
  strings:
    $key_6b0e = { 38 61 [2] 1c 6f [2] 37 43 [2] 19 61 [2] 0d 7a [2] 02 60 [2] 1c 7d [2] 1e 7c [2] 05 7a [2] 19 7d [2] 05 52 }

  condition:
    any of them
}