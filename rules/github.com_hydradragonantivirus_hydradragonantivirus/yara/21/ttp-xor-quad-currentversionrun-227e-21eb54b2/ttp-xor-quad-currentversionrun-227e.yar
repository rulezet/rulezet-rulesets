rule TTP_XOR_QUAD_CurrentVersionRun_227e {
  strings:
    $key_227e = { 71 11 [2] 55 1f [2] 7e 33 [2] 50 11 [2] 44 0a [2] 4b 10 [2] 55 0d [2] 57 0c [2] 4c 0a [2] 50 0d [2] 4c 22 }

  condition:
    any of them
}