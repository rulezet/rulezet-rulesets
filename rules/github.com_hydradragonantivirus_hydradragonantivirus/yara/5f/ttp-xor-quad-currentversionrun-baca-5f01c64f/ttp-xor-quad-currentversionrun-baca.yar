rule TTP_XOR_QUAD_CurrentVersionRun_baca {
  strings:
    $key_baca = { e9 a5 [2] cd ab [2] e6 87 [2] c8 a5 [2] dc be [2] d3 a4 [2] cd b9 [2] cf b8 [2] d4 be [2] c8 b9 [2] d4 96 }

  condition:
    any of them
}