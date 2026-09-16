rule TTP_XOR_QUAD_CurrentVersionRun_ba33 {
  strings:
    $key_ba33 = { e9 5c [2] cd 52 [2] e6 7e [2] c8 5c [2] dc 47 [2] d3 5d [2] cd 40 [2] cf 41 [2] d4 47 [2] c8 40 [2] d4 6f }

  condition:
    any of them
}