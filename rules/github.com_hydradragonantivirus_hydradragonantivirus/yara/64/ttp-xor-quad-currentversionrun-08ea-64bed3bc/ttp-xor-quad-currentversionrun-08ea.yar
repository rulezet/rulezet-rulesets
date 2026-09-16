rule TTP_XOR_QUAD_CurrentVersionRun_08ea {
  strings:
    $key_08ea = { 5b 85 [2] 7f 8b [2] 54 a7 [2] 7a 85 [2] 6e 9e [2] 61 84 [2] 7f 99 [2] 7d 98 [2] 66 9e [2] 7a 99 [2] 66 b6 }

  condition:
    any of them
}