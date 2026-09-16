rule TTP_XOR_QUAD_CurrentVersionRun_ba12 {
  strings:
    $key_ba12 = { e9 7d [2] cd 73 [2] e6 5f [2] c8 7d [2] dc 66 [2] d3 7c [2] cd 61 [2] cf 60 [2] d4 66 [2] c8 61 [2] d4 4e }

  condition:
    any of them
}