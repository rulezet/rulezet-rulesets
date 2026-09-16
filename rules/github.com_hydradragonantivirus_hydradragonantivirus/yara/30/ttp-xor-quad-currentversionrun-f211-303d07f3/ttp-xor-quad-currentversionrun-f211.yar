rule TTP_XOR_QUAD_CurrentVersionRun_f211 {
  strings:
    $key_f211 = { a1 7e [2] 85 70 [2] ae 5c [2] 80 7e [2] 94 65 [2] 9b 7f [2] 85 62 [2] 87 63 [2] 9c 65 [2] 80 62 [2] 9c 4d }

  condition:
    any of them
}