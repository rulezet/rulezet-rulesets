rule TTP_XOR_QUAD_CurrentVersionRun_71ee {
  strings:
    $key_71ee = { 22 81 [2] 06 8f [2] 2d a3 [2] 03 81 [2] 17 9a [2] 18 80 [2] 06 9d [2] 04 9c [2] 1f 9a [2] 03 9d [2] 1f b2 }

  condition:
    any of them
}