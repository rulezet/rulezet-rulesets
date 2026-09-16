rule TTP_XOR_QUAD_CurrentVersionRun_3eee {
  strings:
    $key_3eee = { 6d 81 [2] 49 8f [2] 62 a3 [2] 4c 81 [2] 58 9a [2] 57 80 [2] 49 9d [2] 4b 9c [2] 50 9a [2] 4c 9d [2] 50 b2 }

  condition:
    any of them
}