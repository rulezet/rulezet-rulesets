rule TTP_XOR_QUAD_CurrentVersionRun_ba6a {
  strings:
    $key_ba6a = { e9 05 [2] cd 0b [2] e6 27 [2] c8 05 [2] dc 1e [2] d3 04 [2] cd 19 [2] cf 18 [2] d4 1e [2] c8 19 [2] d4 36 }

  condition:
    any of them
}