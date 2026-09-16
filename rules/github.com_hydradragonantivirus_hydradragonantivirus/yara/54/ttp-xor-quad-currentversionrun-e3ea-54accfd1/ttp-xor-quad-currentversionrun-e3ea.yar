rule TTP_XOR_QUAD_CurrentVersionRun_e3ea {
  strings:
    $key_e3ea = { b0 85 [2] 94 8b [2] bf a7 [2] 91 85 [2] 85 9e [2] 8a 84 [2] 94 99 [2] 96 98 [2] 8d 9e [2] 91 99 [2] 8d b6 }

  condition:
    any of them
}