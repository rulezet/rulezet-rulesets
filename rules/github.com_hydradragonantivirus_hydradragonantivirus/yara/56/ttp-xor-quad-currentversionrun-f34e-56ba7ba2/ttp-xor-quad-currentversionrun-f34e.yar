rule TTP_XOR_QUAD_CurrentVersionRun_f34e {
  strings:
    $key_f34e = { a0 21 [2] 84 2f [2] af 03 [2] 81 21 [2] 95 3a [2] 9a 20 [2] 84 3d [2] 86 3c [2] 9d 3a [2] 81 3d [2] 9d 12 }

  condition:
    any of them
}