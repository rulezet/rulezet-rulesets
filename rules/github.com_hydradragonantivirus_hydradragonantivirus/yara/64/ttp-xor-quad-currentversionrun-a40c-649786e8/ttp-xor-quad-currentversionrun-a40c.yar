rule TTP_XOR_QUAD_CurrentVersionRun_a40c {
  strings:
    $key_a40c = { f7 63 [2] d3 6d [2] f8 41 [2] d6 63 [2] c2 78 [2] cd 62 [2] d3 7f [2] d1 7e [2] ca 78 [2] d6 7f [2] ca 50 }

  condition:
    any of them
}