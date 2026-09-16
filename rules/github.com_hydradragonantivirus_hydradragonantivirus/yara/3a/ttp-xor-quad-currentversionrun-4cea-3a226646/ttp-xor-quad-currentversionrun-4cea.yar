rule TTP_XOR_QUAD_CurrentVersionRun_4cea {
  strings:
    $key_4cea = { 1f 85 [2] 3b 8b [2] 10 a7 [2] 3e 85 [2] 2a 9e [2] 25 84 [2] 3b 99 [2] 39 98 [2] 22 9e [2] 3e 99 [2] 22 b6 }

  condition:
    any of them
}