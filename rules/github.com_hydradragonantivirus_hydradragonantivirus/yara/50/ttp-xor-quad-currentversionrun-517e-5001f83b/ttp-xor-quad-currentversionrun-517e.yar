rule TTP_XOR_QUAD_CurrentVersionRun_517e {
  strings:
    $key_517e = { 02 11 [2] 26 1f [2] 0d 33 [2] 23 11 [2] 37 0a [2] 38 10 [2] 26 0d [2] 24 0c [2] 3f 0a [2] 23 0d [2] 3f 22 }

  condition:
    any of them
}