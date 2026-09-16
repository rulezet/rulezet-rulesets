rule TTP_XOR_QUAD_CurrentVersionRun_f64e {
  strings:
    $key_f64e = { a5 21 [2] 81 2f [2] aa 03 [2] 84 21 [2] 90 3a [2] 9f 20 [2] 81 3d [2] 83 3c [2] 98 3a [2] 84 3d [2] 98 12 }

  condition:
    any of them
}