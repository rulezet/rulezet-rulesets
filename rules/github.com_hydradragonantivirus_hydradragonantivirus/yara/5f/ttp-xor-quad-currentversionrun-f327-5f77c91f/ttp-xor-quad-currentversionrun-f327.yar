rule TTP_XOR_QUAD_CurrentVersionRun_f327 {
  strings:
    $key_f327 = { a0 48 [2] 84 46 [2] af 6a [2] 81 48 [2] 95 53 [2] 9a 49 [2] 84 54 [2] 86 55 [2] 9d 53 [2] 81 54 [2] 9d 7b }

  condition:
    any of them
}