rule TTP_XOR_QUAD_CurrentVersionRun_ba14 {
  strings:
    $key_ba14 = { e9 7b [2] cd 75 [2] e6 59 [2] c8 7b [2] dc 60 [2] d3 7a [2] cd 67 [2] cf 66 [2] d4 60 [2] c8 67 [2] d4 48 }

  condition:
    any of them
}