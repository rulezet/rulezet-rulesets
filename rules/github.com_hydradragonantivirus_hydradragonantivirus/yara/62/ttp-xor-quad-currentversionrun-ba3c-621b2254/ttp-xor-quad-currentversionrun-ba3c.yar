rule TTP_XOR_QUAD_CurrentVersionRun_ba3c {
  strings:
    $key_ba3c = { e9 53 [2] cd 5d [2] e6 71 [2] c8 53 [2] dc 48 [2] d3 52 [2] cd 4f [2] cf 4e [2] d4 48 [2] c8 4f [2] d4 60 }

  condition:
    any of them
}