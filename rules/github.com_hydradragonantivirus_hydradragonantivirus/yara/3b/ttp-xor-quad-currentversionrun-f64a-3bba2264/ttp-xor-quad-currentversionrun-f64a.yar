rule TTP_XOR_QUAD_CurrentVersionRun_f64a {
  strings:
    $key_f64a = { a5 25 [2] 81 2b [2] aa 07 [2] 84 25 [2] 90 3e [2] 9f 24 [2] 81 39 [2] 83 38 [2] 98 3e [2] 84 39 [2] 98 16 }

  condition:
    any of them
}