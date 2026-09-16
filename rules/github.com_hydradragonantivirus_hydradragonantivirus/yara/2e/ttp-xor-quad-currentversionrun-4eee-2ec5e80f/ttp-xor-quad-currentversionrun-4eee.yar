rule TTP_XOR_QUAD_CurrentVersionRun_4eee {
  strings:
    $key_4eee = { 1d 81 [2] 39 8f [2] 12 a3 [2] 3c 81 [2] 28 9a [2] 27 80 [2] 39 9d [2] 3b 9c [2] 20 9a [2] 3c 9d [2] 20 b2 }

  condition:
    any of them
}