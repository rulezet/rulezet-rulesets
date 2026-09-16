rule TTP_XOR_QUAD_CurrentVersionRun_ba6d {
  strings:
    $key_ba6d = { e9 02 [2] cd 0c [2] e6 20 [2] c8 02 [2] dc 19 [2] d3 03 [2] cd 1e [2] cf 1f [2] d4 19 [2] c8 1e [2] d4 31 }

  condition:
    any of them
}