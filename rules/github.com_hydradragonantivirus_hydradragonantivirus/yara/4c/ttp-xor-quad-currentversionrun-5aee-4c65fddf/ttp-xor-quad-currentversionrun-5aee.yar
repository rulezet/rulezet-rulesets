rule TTP_XOR_QUAD_CurrentVersionRun_5aee {
  strings:
    $key_5aee = { 09 81 [2] 2d 8f [2] 06 a3 [2] 28 81 [2] 3c 9a [2] 33 80 [2] 2d 9d [2] 2f 9c [2] 34 9a [2] 28 9d [2] 34 b2 }

  condition:
    any of them
}