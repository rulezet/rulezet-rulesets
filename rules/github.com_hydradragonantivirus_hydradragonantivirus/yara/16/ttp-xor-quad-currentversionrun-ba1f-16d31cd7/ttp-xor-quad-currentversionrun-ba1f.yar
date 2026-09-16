rule TTP_XOR_QUAD_CurrentVersionRun_ba1f {
  strings:
    $key_ba1f = { e9 70 [2] cd 7e [2] e6 52 [2] c8 70 [2] dc 6b [2] d3 71 [2] cd 6c [2] cf 6d [2] d4 6b [2] c8 6c [2] d4 43 }

  condition:
    any of them
}