rule TTP_XOR_QUAD_CurrentVersionRun_baea {
  strings:
    $key_baea = { e9 85 [2] cd 8b [2] e6 a7 [2] c8 85 [2] dc 9e [2] d3 84 [2] cd 99 [2] cf 98 [2] d4 9e [2] c8 99 [2] d4 b6 }

  condition:
    any of them
}