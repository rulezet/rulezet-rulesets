rule TTP_XOR_QUAD_CurrentVersionRun_6bee {
  strings:
    $key_6bee = { 38 81 [2] 1c 8f [2] 37 a3 [2] 19 81 [2] 0d 9a [2] 02 80 [2] 1c 9d [2] 1e 9c [2] 05 9a [2] 19 9d [2] 05 b2 }

  condition:
    any of them
}