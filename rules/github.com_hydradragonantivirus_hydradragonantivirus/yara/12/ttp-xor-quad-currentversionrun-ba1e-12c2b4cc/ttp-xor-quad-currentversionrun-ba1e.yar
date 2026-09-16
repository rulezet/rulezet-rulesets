rule TTP_XOR_QUAD_CurrentVersionRun_ba1e {
  strings:
    $key_ba1e = { e9 71 [2] cd 7f [2] e6 53 [2] c8 71 [2] dc 6a [2] d3 70 [2] cd 6d [2] cf 6c [2] d4 6a [2] c8 6d [2] d4 42 }

  condition:
    any of them
}