rule TTP_XOR_QUAD_CurrentVersionRun_a4c5 {
  strings:
    $key_a4c5 = { f7 aa [2] d3 a4 [2] f8 88 [2] d6 aa [2] c2 b1 [2] cd ab [2] d3 b6 [2] d1 b7 [2] ca b1 [2] d6 b6 [2] ca 99 }

  condition:
    any of them
}