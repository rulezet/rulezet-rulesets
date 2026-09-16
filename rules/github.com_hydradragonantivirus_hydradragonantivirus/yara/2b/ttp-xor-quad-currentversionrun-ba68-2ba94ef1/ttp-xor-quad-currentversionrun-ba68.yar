rule TTP_XOR_QUAD_CurrentVersionRun_ba68 {
  strings:
    $key_ba68 = { e9 07 [2] cd 09 [2] e6 25 [2] c8 07 [2] dc 1c [2] d3 06 [2] cd 1b [2] cf 1a [2] d4 1c [2] c8 1b [2] d4 34 }

  condition:
    any of them
}