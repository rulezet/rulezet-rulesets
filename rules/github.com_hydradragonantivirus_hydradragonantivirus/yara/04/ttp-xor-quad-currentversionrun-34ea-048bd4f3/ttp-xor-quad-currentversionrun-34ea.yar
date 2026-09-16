rule TTP_XOR_QUAD_CurrentVersionRun_34ea {
  strings:
    $key_34ea = { 67 85 [2] 43 8b [2] 68 a7 [2] 46 85 [2] 52 9e [2] 5d 84 [2] 43 99 [2] 41 98 [2] 5a 9e [2] 46 99 [2] 5a b6 }

  condition:
    any of them
}