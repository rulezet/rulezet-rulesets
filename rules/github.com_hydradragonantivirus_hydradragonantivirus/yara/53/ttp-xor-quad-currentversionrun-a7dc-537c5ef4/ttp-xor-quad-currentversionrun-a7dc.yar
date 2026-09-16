rule TTP_XOR_QUAD_CurrentVersionRun_a7dc {
  strings:
    $key_a7dc = { f4 b3 [2] d0 bd [2] fb 91 [2] d5 b3 [2] c1 a8 [2] ce b2 [2] d0 af [2] d2 ae [2] c9 a8 [2] d5 af [2] c9 80 }

  condition:
    any of them
}