rule TTP_XOR_QUAD_CurrentVersionRun_f76b {
  strings:
    $key_f76b = { a4 04 [2] 80 0a [2] ab 26 [2] 85 04 [2] 91 1f [2] 9e 05 [2] 80 18 [2] 82 19 [2] 99 1f [2] 85 18 [2] 99 37 }

  condition:
    any of them
}