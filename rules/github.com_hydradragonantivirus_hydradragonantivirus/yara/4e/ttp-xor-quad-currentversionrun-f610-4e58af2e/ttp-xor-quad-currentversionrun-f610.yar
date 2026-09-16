rule TTP_XOR_QUAD_CurrentVersionRun_f610 {
  strings:
    $key_f610 = { a5 7f [2] 81 71 [2] aa 5d [2] 84 7f [2] 90 64 [2] 9f 7e [2] 81 63 [2] 83 62 [2] 98 64 [2] 84 63 [2] 98 4c }

  condition:
    any of them
}