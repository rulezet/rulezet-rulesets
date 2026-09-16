rule TTP_XOR_QUAD_CurrentVersionRun_0cee {
  strings:
    $key_0cee = { 5f 81 [2] 7b 8f [2] 50 a3 [2] 7e 81 [2] 6a 9a [2] 65 80 [2] 7b 9d [2] 79 9c [2] 62 9a [2] 7e 9d [2] 62 b2 }

  condition:
    any of them
}