rule TTP_XOR_QUAD_CurrentVersionRun_ef4e {
  strings:
    $key_ef4e = { bc 21 [2] 98 2f [2] b3 03 [2] 9d 21 [2] 89 3a [2] 86 20 [2] 98 3d [2] 9a 3c [2] 81 3a [2] 9d 3d [2] 81 12 }

  condition:
    any of them
}