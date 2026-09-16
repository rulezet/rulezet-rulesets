rule TTP_XOR_QUAD_CurrentVersionRun_397e {
  strings:
    $key_397e = { 6a 11 [2] 4e 1f [2] 65 33 [2] 4b 11 [2] 5f 0a [2] 50 10 [2] 4e 0d [2] 4c 0c [2] 57 0a [2] 4b 0d [2] 57 22 }

  condition:
    any of them
}