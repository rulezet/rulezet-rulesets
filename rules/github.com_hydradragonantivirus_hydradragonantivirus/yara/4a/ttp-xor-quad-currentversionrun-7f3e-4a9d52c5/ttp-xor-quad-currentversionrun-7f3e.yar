rule TTP_XOR_QUAD_CurrentVersionRun_7f3e {
  strings:
    $key_7f3e = { 2c 51 [2] 08 5f [2] 23 73 [2] 0d 51 [2] 19 4a [2] 16 50 [2] 08 4d [2] 0a 4c [2] 11 4a [2] 0d 4d [2] 11 62 }

  condition:
    any of them
}