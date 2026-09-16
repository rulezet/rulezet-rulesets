rule TTP_XOR_QUAD_CurrentVersionRun_ba4f {
  strings:
    $key_ba4f = { e9 20 [2] cd 2e [2] e6 02 [2] c8 20 [2] dc 3b [2] d3 21 [2] cd 3c [2] cf 3d [2] d4 3b [2] c8 3c [2] d4 13 }

  condition:
    any of them
}