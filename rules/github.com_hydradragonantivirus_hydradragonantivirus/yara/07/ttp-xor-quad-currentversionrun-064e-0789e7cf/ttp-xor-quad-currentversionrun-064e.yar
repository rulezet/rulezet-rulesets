rule TTP_XOR_QUAD_CurrentVersionRun_064e {
  strings:
    $key_064e = { 55 21 [2] 71 2f [2] 5a 03 [2] 74 21 [2] 60 3a [2] 6f 20 [2] 71 3d [2] 73 3c [2] 68 3a [2] 74 3d [2] 68 12 }

  condition:
    any of them
}