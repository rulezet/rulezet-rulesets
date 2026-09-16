rule TTP_XOR_QUAD_CurrentVersionRun_ba3e {
  strings:
    $key_ba3e = { e9 51 [2] cd 5f [2] e6 73 [2] c8 51 [2] dc 4a [2] d3 50 [2] cd 4d [2] cf 4c [2] d4 4a [2] c8 4d [2] d4 62 }

  condition:
    any of them
}