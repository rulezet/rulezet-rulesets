rule TTP_XOR_QUAD_CurrentVersionRun_f671 {
  strings:
    $key_f671 = { a5 1e [2] 81 10 [2] aa 3c [2] 84 1e [2] 90 05 [2] 9f 1f [2] 81 02 [2] 83 03 [2] 98 05 [2] 84 02 [2] 98 2d }

  condition:
    any of them
}