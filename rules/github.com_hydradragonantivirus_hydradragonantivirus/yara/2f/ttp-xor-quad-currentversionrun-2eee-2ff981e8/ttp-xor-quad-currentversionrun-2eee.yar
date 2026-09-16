rule TTP_XOR_QUAD_CurrentVersionRun_2eee {
  strings:
    $key_2eee = { 7d 81 [2] 59 8f [2] 72 a3 [2] 5c 81 [2] 48 9a [2] 47 80 [2] 59 9d [2] 5b 9c [2] 40 9a [2] 5c 9d [2] 40 b2 }

  condition:
    any of them
}