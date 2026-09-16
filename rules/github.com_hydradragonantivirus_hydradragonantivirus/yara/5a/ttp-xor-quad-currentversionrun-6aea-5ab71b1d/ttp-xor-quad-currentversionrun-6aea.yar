rule TTP_XOR_QUAD_CurrentVersionRun_6aea {
  strings:
    $key_6aea = { 39 85 [2] 1d 8b [2] 36 a7 [2] 18 85 [2] 0c 9e [2] 03 84 [2] 1d 99 [2] 1f 98 [2] 04 9e [2] 18 99 [2] 04 b6 }

  condition:
    any of them
}