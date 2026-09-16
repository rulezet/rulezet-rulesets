rule TTP_XOR_QUAD_CurrentVersionRun_a471 {
  strings:
    $key_a471 = { f7 1e [2] d3 10 [2] f8 3c [2] d6 1e [2] c2 05 [2] cd 1f [2] d3 02 [2] d1 03 [2] ca 05 [2] d6 02 [2] ca 2d }

  condition:
    any of them
}