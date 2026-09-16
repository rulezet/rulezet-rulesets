rule TTP_XOR_QUAD_CurrentVersionRun_1f2e {
  strings:
    $key_1f2e = { 4c 41 [2] 68 4f [2] 43 63 [2] 6d 41 [2] 79 5a [2] 76 40 [2] 68 5d [2] 6a 5c [2] 71 5a [2] 6d 5d [2] 71 72 }

  condition:
    any of them
}