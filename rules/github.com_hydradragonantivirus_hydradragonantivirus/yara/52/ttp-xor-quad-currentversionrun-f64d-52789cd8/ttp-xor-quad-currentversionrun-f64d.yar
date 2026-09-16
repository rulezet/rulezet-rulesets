rule TTP_XOR_QUAD_CurrentVersionRun_f64d {
  strings:
    $key_f64d = { a5 22 [2] 81 2c [2] aa 00 [2] 84 22 [2] 90 39 [2] 9f 23 [2] 81 3e [2] 83 3f [2] 98 39 [2] 84 3e [2] 98 11 }

  condition:
    any of them
}