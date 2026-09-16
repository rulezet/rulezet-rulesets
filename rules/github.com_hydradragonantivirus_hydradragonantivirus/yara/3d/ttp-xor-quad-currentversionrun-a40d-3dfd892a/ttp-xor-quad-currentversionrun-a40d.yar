rule TTP_XOR_QUAD_CurrentVersionRun_a40d {
  strings:
    $key_a40d = { f7 62 [2] d3 6c [2] f8 40 [2] d6 62 [2] c2 79 [2] cd 63 [2] d3 7e [2] d1 7f [2] ca 79 [2] d6 7e [2] ca 51 }

  condition:
    any of them
}