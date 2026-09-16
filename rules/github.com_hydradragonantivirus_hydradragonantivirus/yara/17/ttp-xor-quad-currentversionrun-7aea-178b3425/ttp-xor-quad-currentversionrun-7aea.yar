rule TTP_XOR_QUAD_CurrentVersionRun_7aea {
  strings:
    $key_7aea = { 29 85 [2] 0d 8b [2] 26 a7 [2] 08 85 [2] 1c 9e [2] 13 84 [2] 0d 99 [2] 0f 98 [2] 14 9e [2] 08 99 [2] 14 b6 }

  condition:
    any of them
}