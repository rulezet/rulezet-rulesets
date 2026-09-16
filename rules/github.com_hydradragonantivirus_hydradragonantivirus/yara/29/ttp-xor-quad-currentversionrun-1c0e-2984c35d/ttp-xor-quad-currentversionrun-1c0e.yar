rule TTP_XOR_QUAD_CurrentVersionRun_1c0e {
  strings:
    $key_1c0e = { 4f 61 [2] 6b 6f [2] 40 43 [2] 6e 61 [2] 7a 7a [2] 75 60 [2] 6b 7d [2] 69 7c [2] 72 7a [2] 6e 7d [2] 72 52 }

  condition:
    any of them
}