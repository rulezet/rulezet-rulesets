rule TTP_XOR_QUAD_CurrentVersionRun_ab6b {
  strings:
    $key_ab6b = { f8 04 [2] dc 0a [2] f7 26 [2] d9 04 [2] cd 1f [2] c2 05 [2] dc 18 [2] de 19 [2] c5 1f [2] d9 18 [2] c5 37 }

  condition:
    any of them
}