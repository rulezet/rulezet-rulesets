rule TTP_XOR_QUAD_CurrentVersionRun_f621 {
  strings:
    $key_f621 = { a5 4e [2] 81 40 [2] aa 6c [2] 84 4e [2] 90 55 [2] 9f 4f [2] 81 52 [2] 83 53 [2] 98 55 [2] 84 52 [2] 98 7d }

  condition:
    any of them
}