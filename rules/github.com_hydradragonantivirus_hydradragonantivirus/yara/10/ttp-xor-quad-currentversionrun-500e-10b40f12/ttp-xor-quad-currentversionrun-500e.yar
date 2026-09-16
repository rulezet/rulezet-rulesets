rule TTP_XOR_QUAD_CurrentVersionRun_500e {
  strings:
    $key_500e = { 03 61 [2] 27 6f [2] 0c 43 [2] 22 61 [2] 36 7a [2] 39 60 [2] 27 7d [2] 25 7c [2] 3e 7a [2] 22 7d [2] 3e 52 }

  condition:
    any of them
}