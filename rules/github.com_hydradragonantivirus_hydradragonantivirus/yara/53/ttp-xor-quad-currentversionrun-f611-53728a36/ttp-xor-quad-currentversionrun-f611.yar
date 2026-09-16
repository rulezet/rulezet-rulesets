rule TTP_XOR_QUAD_CurrentVersionRun_f611 {
  strings:
    $key_f611 = { a5 7e [2] 81 70 [2] aa 5c [2] 84 7e [2] 90 65 [2] 9f 7f [2] 81 62 [2] 83 63 [2] 98 65 [2] 84 62 [2] 98 4d }

  condition:
    any of them
}