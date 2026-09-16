rule TTP_XOR_QUAD_CurrentVersionRun_23ea {
  strings:
    $key_23ea = { 70 85 [2] 54 8b [2] 7f a7 [2] 51 85 [2] 45 9e [2] 4a 84 [2] 54 99 [2] 56 98 [2] 4d 9e [2] 51 99 [2] 4d b6 }

  condition:
    any of them
}