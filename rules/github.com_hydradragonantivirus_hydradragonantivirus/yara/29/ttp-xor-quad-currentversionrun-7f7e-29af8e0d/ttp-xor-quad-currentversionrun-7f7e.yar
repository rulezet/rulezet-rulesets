rule TTP_XOR_QUAD_CurrentVersionRun_7f7e {
  strings:
    $key_7f7e = { 2c 11 [2] 08 1f [2] 23 33 [2] 0d 11 [2] 19 0a [2] 16 10 [2] 08 0d [2] 0a 0c [2] 11 0a [2] 0d 0d [2] 11 22 }

  condition:
    any of them
}