rule TTP_XOR_QUAD_CurrentVersionRun_f50e {
  strings:
    $key_f50e = { a6 61 [2] 82 6f [2] a9 43 [2] 87 61 [2] 93 7a [2] 9c 60 [2] 82 7d [2] 80 7c [2] 9b 7a [2] 87 7d [2] 9b 52 }

  condition:
    any of them
}