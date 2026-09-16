rule TTP_XOR_QUAD_CurrentVersionRun_bafe {
  strings:
    $key_bafe = { e9 91 [2] cd 9f [2] e6 b3 [2] c8 91 [2] dc 8a [2] d3 90 [2] cd 8d [2] cf 8c [2] d4 8a [2] c8 8d [2] d4 a2 }

  condition:
    any of them
}