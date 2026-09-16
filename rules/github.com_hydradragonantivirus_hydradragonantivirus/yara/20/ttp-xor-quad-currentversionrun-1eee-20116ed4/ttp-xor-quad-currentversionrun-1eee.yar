rule TTP_XOR_QUAD_CurrentVersionRun_1eee {
  strings:
    $key_1eee = { 4d 81 [2] 69 8f [2] 42 a3 [2] 6c 81 [2] 78 9a [2] 77 80 [2] 69 9d [2] 6b 9c [2] 70 9a [2] 6c 9d [2] 70 b2 }

  condition:
    any of them
}