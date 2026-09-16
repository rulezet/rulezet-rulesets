rule TTP_XOR_QUAD_CurrentVersionRun_f66c {
  strings:
    $key_f66c = { a5 03 [2] 81 0d [2] aa 21 [2] 84 03 [2] 90 18 [2] 9f 02 [2] 81 1f [2] 83 1e [2] 98 18 [2] 84 1f [2] 98 30 }

  condition:
    any of them
}