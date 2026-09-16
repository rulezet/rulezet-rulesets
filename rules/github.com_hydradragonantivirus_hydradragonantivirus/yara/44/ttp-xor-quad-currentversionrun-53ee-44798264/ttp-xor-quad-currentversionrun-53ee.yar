rule TTP_XOR_QUAD_CurrentVersionRun_53ee {
  strings:
    $key_53ee = { 00 81 [2] 24 8f [2] 0f a3 [2] 21 81 [2] 35 9a [2] 3a 80 [2] 24 9d [2] 26 9c [2] 3d 9a [2] 21 9d [2] 3d b2 }

  condition:
    any of them
}