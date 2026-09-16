rule TTP_XOR_QUAD_CurrentVersionRun_13ee {
  strings:
    $key_13ee = { 40 81 [2] 64 8f [2] 4f a3 [2] 61 81 [2] 75 9a [2] 7a 80 [2] 64 9d [2] 66 9c [2] 7d 9a [2] 61 9d [2] 7d b2 }

  condition:
    any of them
}