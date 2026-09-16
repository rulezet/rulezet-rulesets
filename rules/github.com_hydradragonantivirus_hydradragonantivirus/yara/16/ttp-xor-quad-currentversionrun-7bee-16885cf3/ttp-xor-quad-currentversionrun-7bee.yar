rule TTP_XOR_QUAD_CurrentVersionRun_7bee {
  strings:
    $key_7bee = { 28 81 [2] 0c 8f [2] 27 a3 [2] 09 81 [2] 1d 9a [2] 12 80 [2] 0c 9d [2] 0e 9c [2] 15 9a [2] 09 9d [2] 15 b2 }

  condition:
    any of them
}