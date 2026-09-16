rule TTP_XOR_QUAD_CurrentVersionRun_22ea {
  strings:
    $key_22ea = { 71 85 [2] 55 8b [2] 7e a7 [2] 50 85 [2] 44 9e [2] 4b 84 [2] 55 99 [2] 57 98 [2] 4c 9e [2] 50 99 [2] 4c b6 }

  condition:
    any of them
}