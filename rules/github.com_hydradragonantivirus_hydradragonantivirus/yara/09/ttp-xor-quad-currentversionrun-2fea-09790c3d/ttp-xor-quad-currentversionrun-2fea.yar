rule TTP_XOR_QUAD_CurrentVersionRun_2fea {
  strings:
    $key_2fea = { 7c 85 [2] 58 8b [2] 73 a7 [2] 5d 85 [2] 49 9e [2] 46 84 [2] 58 99 [2] 5a 98 [2] 41 9e [2] 5d 99 [2] 41 b6 }

  condition:
    any of them
}