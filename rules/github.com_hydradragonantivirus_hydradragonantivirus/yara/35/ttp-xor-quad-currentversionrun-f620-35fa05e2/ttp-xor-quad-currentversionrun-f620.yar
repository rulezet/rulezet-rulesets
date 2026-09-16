rule TTP_XOR_QUAD_CurrentVersionRun_f620 {
  strings:
    $key_f620 = { a5 4f [2] 81 41 [2] aa 6d [2] 84 4f [2] 90 54 [2] 9f 4e [2] 81 53 [2] 83 52 [2] 98 54 [2] 84 53 [2] 98 7c }

  condition:
    any of them
}