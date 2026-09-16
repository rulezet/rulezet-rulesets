rule TTP_XOR_QUAD_CurrentVersionRun_2a1e {
  strings:
    $key_2a1e = { 79 71 [2] 5d 7f [2] 76 53 [2] 58 71 [2] 4c 6a [2] 43 70 [2] 5d 6d [2] 5f 6c [2] 44 6a [2] 58 6d [2] 44 42 }

  condition:
    any of them
}