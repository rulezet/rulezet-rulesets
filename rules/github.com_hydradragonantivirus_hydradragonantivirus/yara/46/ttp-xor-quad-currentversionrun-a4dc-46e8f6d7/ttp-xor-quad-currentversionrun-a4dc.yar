rule TTP_XOR_QUAD_CurrentVersionRun_a4dc {
  strings:
    $key_a4dc = { f7 b3 [2] d3 bd [2] f8 91 [2] d6 b3 [2] c2 a8 [2] cd b2 [2] d3 af [2] d1 ae [2] ca a8 [2] d6 af [2] ca 80 }

  condition:
    any of them
}