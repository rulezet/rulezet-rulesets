rule TTP_XOR_QUAD_CurrentVersionRun_7aee {
  strings:
    $key_7aee = { 29 81 [2] 0d 8f [2] 26 a3 [2] 08 81 [2] 1c 9a [2] 13 80 [2] 0d 9d [2] 0f 9c [2] 14 9a [2] 08 9d [2] 14 b2 }

  condition:
    any of them
}