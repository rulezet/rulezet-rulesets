rule TTP_XOR_QUAD_CurrentVersionRun_f7ea {
  strings:
    $key_f7ea = { a4 85 [2] 80 8b [2] ab a7 [2] 85 85 [2] 91 9e [2] 9e 84 [2] 80 99 [2] 82 98 [2] 99 9e [2] 85 99 [2] 99 b6 }

  condition:
    any of them
}