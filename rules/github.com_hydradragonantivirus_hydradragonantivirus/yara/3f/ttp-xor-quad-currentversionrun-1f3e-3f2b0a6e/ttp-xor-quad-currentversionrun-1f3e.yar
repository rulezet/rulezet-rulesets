rule TTP_XOR_QUAD_CurrentVersionRun_1f3e {
  strings:
    $key_1f3e = { 4c 51 [2] 68 5f [2] 43 73 [2] 6d 51 [2] 79 4a [2] 76 50 [2] 68 4d [2] 6a 4c [2] 71 4a [2] 6d 4d [2] 71 62 }

  condition:
    any of them
}