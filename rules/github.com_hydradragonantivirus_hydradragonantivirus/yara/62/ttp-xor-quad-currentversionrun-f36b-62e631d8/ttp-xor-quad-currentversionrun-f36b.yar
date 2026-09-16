rule TTP_XOR_QUAD_CurrentVersionRun_f36b {
  strings:
    $key_f36b = { a0 04 [2] 84 0a [2] af 26 [2] 81 04 [2] 95 1f [2] 9a 05 [2] 84 18 [2] 86 19 [2] 9d 1f [2] 81 18 [2] 9d 37 }

  condition:
    any of them
}