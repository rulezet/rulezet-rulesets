rule TTP_XOR_QUAD_CurrentVersionRun_f33b {
  strings:
    $key_f33b = { a0 54 [2] 84 5a [2] af 76 [2] 81 54 [2] 95 4f [2] 9a 55 [2] 84 48 [2] 86 49 [2] 9d 4f [2] 81 48 [2] 9d 67 }

  condition:
    any of them
}