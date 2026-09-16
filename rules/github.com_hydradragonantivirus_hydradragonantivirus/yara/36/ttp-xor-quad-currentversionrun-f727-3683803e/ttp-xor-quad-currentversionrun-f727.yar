rule TTP_XOR_QUAD_CurrentVersionRun_f727 {
  strings:
    $key_f727 = { a4 48 [2] 80 46 [2] ab 6a [2] 85 48 [2] 91 53 [2] 9e 49 [2] 80 54 [2] 82 55 [2] 99 53 [2] 85 54 [2] 99 7b }

  condition:
    any of them
}