rule TTP_XOR_QUAD_CurrentVersionRun_a9dc {
  strings:
    $key_a9dc = { fa b3 [2] de bd [2] f5 91 [2] db b3 [2] cf a8 [2] c0 b2 [2] de af [2] dc ae [2] c7 a8 [2] db af [2] c7 80 }

  condition:
    any of them
}