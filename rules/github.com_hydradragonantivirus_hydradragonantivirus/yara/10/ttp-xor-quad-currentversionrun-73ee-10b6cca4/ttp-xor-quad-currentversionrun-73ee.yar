rule TTP_XOR_QUAD_CurrentVersionRun_73ee {
  strings:
    $key_73ee = { 20 81 [2] 04 8f [2] 2f a3 [2] 01 81 [2] 15 9a [2] 1a 80 [2] 04 9d [2] 06 9c [2] 1d 9a [2] 01 9d [2] 1d b2 }

  condition:
    any of them
}