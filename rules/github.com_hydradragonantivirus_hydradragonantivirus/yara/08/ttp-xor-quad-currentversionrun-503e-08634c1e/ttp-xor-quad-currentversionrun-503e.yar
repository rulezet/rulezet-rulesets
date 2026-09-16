rule TTP_XOR_QUAD_CurrentVersionRun_503e {
  strings:
    $key_503e = { 03 51 [2] 27 5f [2] 0c 73 [2] 22 51 [2] 36 4a [2] 39 50 [2] 27 4d [2] 25 4c [2] 3e 4a [2] 22 4d [2] 3e 62 }

  condition:
    any of them
}