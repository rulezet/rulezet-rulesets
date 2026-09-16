rule TTP_XOR_QUAD_CurrentVersionRun_e5ea {
  strings:
    $key_e5ea = { b6 85 [2] 92 8b [2] b9 a7 [2] 97 85 [2] 83 9e [2] 8c 84 [2] 92 99 [2] 90 98 [2] 8b 9e [2] 97 99 [2] 8b b6 }

  condition:
    any of them
}