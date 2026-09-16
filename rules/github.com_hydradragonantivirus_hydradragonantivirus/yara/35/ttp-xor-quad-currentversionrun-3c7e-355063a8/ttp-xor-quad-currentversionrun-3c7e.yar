rule TTP_XOR_QUAD_CurrentVersionRun_3c7e {
  strings:
    $key_3c7e = { 6f 11 [2] 4b 1f [2] 60 33 [2] 4e 11 [2] 5a 0a [2] 55 10 [2] 4b 0d [2] 49 0c [2] 52 0a [2] 4e 0d [2] 52 22 }

  condition:
    any of them
}