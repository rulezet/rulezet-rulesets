rule TTP_XOR_QUAD_CurrentVersionRun_f311 {
  strings:
    $key_f311 = { a0 7e [2] 84 70 [2] af 5c [2] 81 7e [2] 95 65 [2] 9a 7f [2] 84 62 [2] 86 63 [2] 9d 65 [2] 81 62 [2] 9d 4d }

  condition:
    any of them
}