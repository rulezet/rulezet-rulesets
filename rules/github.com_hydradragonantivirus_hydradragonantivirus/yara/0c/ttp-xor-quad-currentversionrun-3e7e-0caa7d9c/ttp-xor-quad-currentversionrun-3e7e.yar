rule TTP_XOR_QUAD_CurrentVersionRun_3e7e {
  strings:
    $key_3e7e = { 6d 11 [2] 49 1f [2] 62 33 [2] 4c 11 [2] 58 0a [2] 57 10 [2] 49 0d [2] 4b 0c [2] 50 0a [2] 4c 0d [2] 50 22 }

  condition:
    any of them
}