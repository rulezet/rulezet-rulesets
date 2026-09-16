rule TTP_XOR_QUAD_CurrentVersionRun_03ee {
  strings:
    $key_03ee = { 50 81 [2] 74 8f [2] 5f a3 [2] 71 81 [2] 65 9a [2] 6a 80 [2] 74 9d [2] 76 9c [2] 6d 9a [2] 71 9d [2] 6d b2 }

  condition:
    any of them
}