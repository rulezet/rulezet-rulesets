rule TTP_XOR_QUAD_CurrentVersionRun_2a2e {
  strings:
    $key_2a2e = { 79 41 [2] 5d 4f [2] 76 63 [2] 58 41 [2] 4c 5a [2] 43 40 [2] 5d 5d [2] 5f 5c [2] 44 5a [2] 58 5d [2] 44 72 }

  condition:
    any of them
}