rule TTP_XOR_QUAD_CurrentVersionRun_4bea {
  strings:
    $key_4bea = { 18 85 [2] 3c 8b [2] 17 a7 [2] 39 85 [2] 2d 9e [2] 22 84 [2] 3c 99 [2] 3e 98 [2] 25 9e [2] 39 99 [2] 25 b6 }

  condition:
    any of them
}