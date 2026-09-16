rule TTP_XOR_QUAD_CurrentVersionRun_0d4e {
  strings:
    $key_0d4e = { 5e 21 [2] 7a 2f [2] 51 03 [2] 7f 21 [2] 6b 3a [2] 64 20 [2] 7a 3d [2] 78 3c [2] 63 3a [2] 7f 3d [2] 63 12 }

  condition:
    any of them
}