rule TTP_XOR_QUAD_CurrentVersionRun_bae2 {
  strings:
    $key_bae2 = { e9 8d [2] cd 83 [2] e6 af [2] c8 8d [2] dc 96 [2] d3 8c [2] cd 91 [2] cf 90 [2] d4 96 [2] c8 91 [2] d4 be }

  condition:
    any of them
}