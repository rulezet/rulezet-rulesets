rule TTP_XOR_QUAD_CurrentVersionRun_bae8 {
  strings:
    $key_bae8 = { e9 87 [2] cd 89 [2] e6 a5 [2] c8 87 [2] dc 9c [2] d3 86 [2] cd 9b [2] cf 9a [2] d4 9c [2] c8 9b [2] d4 b4 }

  condition:
    any of them
}