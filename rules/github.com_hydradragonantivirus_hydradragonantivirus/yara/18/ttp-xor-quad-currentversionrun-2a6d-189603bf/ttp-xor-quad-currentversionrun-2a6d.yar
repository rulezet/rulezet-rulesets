rule TTP_XOR_QUAD_CurrentVersionRun_2a6d {
  strings:
    $key_2a6d = { 79 02 [2] 5d 0c [2] 76 20 [2] 58 02 [2] 4c 19 [2] 43 03 [2] 5d 1e [2] 5f 1f [2] 44 19 [2] 58 1e [2] 44 31 }

  condition:
    any of them
}