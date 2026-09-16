rule TTP_XOR_QUAD_CurrentVersionRun_033e {
  strings:
    $key_033e = { 50 51 [2] 74 5f [2] 5f 73 [2] 71 51 [2] 65 4a [2] 6a 50 [2] 74 4d [2] 76 4c [2] 6d 4a [2] 71 4d [2] 6d 62 }

  condition:
    any of them
}