rule TTP_XOR_QUAD_CurrentVersionRun_7cee {
  strings:
    $key_7cee = { 2f 81 [2] 0b 8f [2] 20 a3 [2] 0e 81 [2] 1a 9a [2] 15 80 [2] 0b 9d [2] 09 9c [2] 12 9a [2] 0e 9d [2] 12 b2 }

  condition:
    any of them
}