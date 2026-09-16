rule TTP_XOR_QUAD_CurrentVersionRun_7a7e {
  strings:
    $key_7a7e = { 29 11 [2] 0d 1f [2] 26 33 [2] 08 11 [2] 1c 0a [2] 13 10 [2] 0d 0d [2] 0f 0c [2] 14 0a [2] 08 0d [2] 14 22 }

  condition:
    any of them
}