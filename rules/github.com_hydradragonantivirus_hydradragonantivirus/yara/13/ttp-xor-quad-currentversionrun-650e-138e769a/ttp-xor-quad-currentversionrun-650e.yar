rule TTP_XOR_QUAD_CurrentVersionRun_650e {
  strings:
    $key_650e = { 36 61 [2] 12 6f [2] 39 43 [2] 17 61 [2] 03 7a [2] 0c 60 [2] 12 7d [2] 10 7c [2] 0b 7a [2] 17 7d [2] 0b 52 }

  condition:
    any of them
}