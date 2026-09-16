rule TTP_XOR_QUAD_CurrentVersionRun_3b7e {
  strings:
    $key_3b7e = { 68 11 [2] 4c 1f [2] 67 33 [2] 49 11 [2] 5d 0a [2] 52 10 [2] 4c 0d [2] 4e 0c [2] 55 0a [2] 49 0d [2] 55 22 }

  condition:
    any of them
}