rule TTP_XOR_QUAD_CurrentVersionRun_0a4e {
  strings:
    $key_0a4e = { 59 21 [2] 7d 2f [2] 56 03 [2] 78 21 [2] 6c 3a [2] 63 20 [2] 7d 3d [2] 7f 3c [2] 64 3a [2] 78 3d [2] 64 12 }

  condition:
    any of them
}