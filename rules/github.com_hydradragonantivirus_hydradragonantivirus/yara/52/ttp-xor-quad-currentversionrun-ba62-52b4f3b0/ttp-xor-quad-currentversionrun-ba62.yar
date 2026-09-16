rule TTP_XOR_QUAD_CurrentVersionRun_ba62 {
  strings:
    $key_ba62 = { e9 0d [2] cd 03 [2] e6 2f [2] c8 0d [2] dc 16 [2] d3 0c [2] cd 11 [2] cf 10 [2] d4 16 [2] c8 11 [2] d4 3e }

  condition:
    any of them
}