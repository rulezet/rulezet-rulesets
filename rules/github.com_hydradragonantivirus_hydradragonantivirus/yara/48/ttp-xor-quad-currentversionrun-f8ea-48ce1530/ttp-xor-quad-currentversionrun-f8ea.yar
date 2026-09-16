rule TTP_XOR_QUAD_CurrentVersionRun_f8ea {
  strings:
    $key_f8ea = { ab 85 [2] 8f 8b [2] a4 a7 [2] 8a 85 [2] 9e 9e [2] 91 84 [2] 8f 99 [2] 8d 98 [2] 96 9e [2] 8a 99 [2] 96 b6 }

  condition:
    any of them
}