rule TTP_XOR_QUAD_CurrentVersionRun_48ee {
  strings:
    $key_48ee = { 1b 81 [2] 3f 8f [2] 14 a3 [2] 3a 81 [2] 2e 9a [2] 21 80 [2] 3f 9d [2] 3d 9c [2] 26 9a [2] 3a 9d [2] 26 b2 }

  condition:
    any of them
}