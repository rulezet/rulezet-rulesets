rule TTP_XOR_QUAD_CurrentVersionRun_ba03 {
  strings:
    $key_ba03 = { e9 6c [2] cd 62 [2] e6 4e [2] c8 6c [2] dc 77 [2] d3 6d [2] cd 70 [2] cf 71 [2] d4 77 [2] c8 70 [2] d4 5f }

  condition:
    any of them
}