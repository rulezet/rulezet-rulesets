rule TTP_XOR_QUAD_CurrentVersionRun_a430 {
  strings:
    $key_a430 = { f7 5f [2] d3 51 [2] f8 7d [2] d6 5f [2] c2 44 [2] cd 5e [2] d3 43 [2] d1 42 [2] ca 44 [2] d6 43 [2] ca 6c }

  condition:
    any of them
}