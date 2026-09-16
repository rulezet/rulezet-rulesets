rule TTP_XOR_QUAD_CurrentVersionRun_ba20 {
  strings:
    $key_ba20 = { e9 4f [2] cd 41 [2] e6 6d [2] c8 4f [2] dc 54 [2] d3 4e [2] cd 53 [2] cf 52 [2] d4 54 [2] c8 53 [2] d4 7c }

  condition:
    any of them
}