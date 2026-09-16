rule TTP_XOR_QUAD_CurrentVersionRun_137e {
  strings:
    $key_137e = { 40 11 [2] 64 1f [2] 4f 33 [2] 61 11 [2] 75 0a [2] 7a 10 [2] 64 0d [2] 66 0c [2] 7d 0a [2] 61 0d [2] 7d 22 }

  condition:
    any of them
}