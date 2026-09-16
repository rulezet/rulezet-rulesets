rule TTP_XOR_QUAD_CurrentVersionRun_1fee {
  strings:
    $key_1fee = { 4c 81 [2] 68 8f [2] 43 a3 [2] 6d 81 [2] 79 9a [2] 76 80 [2] 68 9d [2] 6a 9c [2] 71 9a [2] 6d 9d [2] 71 b2 }

  condition:
    any of them
}