rule TTP_XOR_QUAD_CurrentVersionRun_bafa {
  strings:
    $key_bafa = { e9 95 [2] cd 9b [2] e6 b7 [2] c8 95 [2] dc 8e [2] d3 94 [2] cd 89 [2] cf 88 [2] d4 8e [2] c8 89 [2] d4 a6 }

  condition:
    any of them
}