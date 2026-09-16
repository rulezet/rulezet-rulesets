rule TTP_XOR_QUAD_CurrentVersionRun_a4e2 {
  strings:
    $key_a4e2 = { f7 8d [2] d3 83 [2] f8 af [2] d6 8d [2] c2 96 [2] cd 8c [2] d3 91 [2] d1 90 [2] ca 96 [2] d6 91 [2] ca be }

  condition:
    any of them
}