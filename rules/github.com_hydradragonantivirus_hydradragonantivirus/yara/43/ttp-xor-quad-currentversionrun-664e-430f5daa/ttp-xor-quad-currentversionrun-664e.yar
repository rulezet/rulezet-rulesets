rule TTP_XOR_QUAD_CurrentVersionRun_664e {
  strings:
    $key_664e = { 35 21 [2] 11 2f [2] 3a 03 [2] 14 21 [2] 00 3a [2] 0f 20 [2] 11 3d [2] 13 3c [2] 08 3a [2] 14 3d [2] 08 12 }

  condition:
    any of them
}