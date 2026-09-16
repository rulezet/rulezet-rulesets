rule TTP_XOR_QUAD_CurrentVersionRun_a42f {
  strings:
    $key_a42f = { f7 40 [2] d3 4e [2] f8 62 [2] d6 40 [2] c2 5b [2] cd 41 [2] d3 5c [2] d1 5d [2] ca 5b [2] d6 5c [2] ca 73 }

  condition:
    any of them
}