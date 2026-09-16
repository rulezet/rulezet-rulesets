rule TTP_XOR_QUAD_CurrentVersionRun_6bea {
  strings:
    $key_6bea = { 38 85 [2] 1c 8b [2] 37 a7 [2] 19 85 [2] 0d 9e [2] 02 84 [2] 1c 99 [2] 1e 98 [2] 05 9e [2] 19 99 [2] 05 b6 }

  condition:
    any of them
}