rule TTP_XOR_QUAD_CurrentVersionRun_ba0f {
  strings:
    $key_ba0f = { e9 60 [2] cd 6e [2] e6 42 [2] c8 60 [2] dc 7b [2] d3 61 [2] cd 7c [2] cf 7d [2] d4 7b [2] c8 7c [2] d4 53 }

  condition:
    any of them
}