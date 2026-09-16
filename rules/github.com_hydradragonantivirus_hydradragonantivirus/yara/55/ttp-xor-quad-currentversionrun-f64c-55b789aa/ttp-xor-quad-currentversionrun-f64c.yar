rule TTP_XOR_QUAD_CurrentVersionRun_f64c {
  strings:
    $key_f64c = { a5 23 [2] 81 2d [2] aa 01 [2] 84 23 [2] 90 38 [2] 9f 22 [2] 81 3f [2] 83 3e [2] 98 38 [2] 84 3f [2] 98 10 }

  condition:
    any of them
}