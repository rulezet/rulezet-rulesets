rule TTP_XOR_QUAD_CurrentVersionRun_1a7e {
  strings:
    $key_1a7e = { 49 11 [2] 6d 1f [2] 46 33 [2] 68 11 [2] 7c 0a [2] 73 10 [2] 6d 0d [2] 6f 0c [2] 74 0a [2] 68 0d [2] 74 22 }

  condition:
    any of them
}