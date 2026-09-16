rule TTP_XOR_QUAD_CurrentVersionRun_ba23 {
  strings:
    $key_ba23 = { e9 4c [2] cd 42 [2] e6 6e [2] c8 4c [2] dc 57 [2] d3 4d [2] cd 50 [2] cf 51 [2] d4 57 [2] c8 50 [2] d4 7f }

  condition:
    any of them
}