rule TTP_XOR_QUAD_CurrentVersionRun_4b7e {
  strings:
    $key_4b7e = { 18 11 [2] 3c 1f [2] 17 33 [2] 39 11 [2] 2d 0a [2] 22 10 [2] 3c 0d [2] 3e 0c [2] 25 0a [2] 39 0d [2] 25 22 }

  condition:
    any of them
}