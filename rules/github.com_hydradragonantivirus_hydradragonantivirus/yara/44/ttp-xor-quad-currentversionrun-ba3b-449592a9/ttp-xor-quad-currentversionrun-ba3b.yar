rule TTP_XOR_QUAD_CurrentVersionRun_ba3b {
  strings:
    $key_ba3b = { e9 54 [2] cd 5a [2] e6 76 [2] c8 54 [2] dc 4f [2] d3 55 [2] cd 48 [2] cf 49 [2] d4 4f [2] c8 48 [2] d4 67 }

  condition:
    any of them
}