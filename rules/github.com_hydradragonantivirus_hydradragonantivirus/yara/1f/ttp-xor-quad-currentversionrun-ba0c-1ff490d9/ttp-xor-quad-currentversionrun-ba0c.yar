rule TTP_XOR_QUAD_CurrentVersionRun_ba0c {
  strings:
    $key_ba0c = { e9 63 [2] cd 6d [2] e6 41 [2] c8 63 [2] dc 78 [2] d3 62 [2] cd 7f [2] cf 7e [2] d4 78 [2] c8 7f [2] d4 50 }

  condition:
    any of them
}