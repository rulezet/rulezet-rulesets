rule TTP_XOR_QUAD_CurrentVersionRun_f24e {
  strings:
    $key_f24e = { a1 21 [2] 85 2f [2] ae 03 [2] 80 21 [2] 94 3a [2] 9b 20 [2] 85 3d [2] 87 3c [2] 9c 3a [2] 80 3d [2] 9c 12 }

  condition:
    any of them
}