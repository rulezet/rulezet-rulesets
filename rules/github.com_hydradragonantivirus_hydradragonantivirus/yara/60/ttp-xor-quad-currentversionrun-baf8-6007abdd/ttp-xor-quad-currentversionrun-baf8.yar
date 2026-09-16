rule TTP_XOR_QUAD_CurrentVersionRun_baf8 {
  strings:
    $key_baf8 = { e9 97 [2] cd 99 [2] e6 b5 [2] c8 97 [2] dc 8c [2] d3 96 [2] cd 8b [2] cf 8a [2] d4 8c [2] c8 8b [2] d4 a4 }

  condition:
    any of them
}