rule TTP_XOR_QUAD_CurrentVersionRun_1aee {
  strings:
    $key_1aee = { 49 81 [2] 6d 8f [2] 46 a3 [2] 68 81 [2] 7c 9a [2] 73 80 [2] 6d 9d [2] 6f 9c [2] 74 9a [2] 68 9d [2] 74 b2 }

  condition:
    any of them
}