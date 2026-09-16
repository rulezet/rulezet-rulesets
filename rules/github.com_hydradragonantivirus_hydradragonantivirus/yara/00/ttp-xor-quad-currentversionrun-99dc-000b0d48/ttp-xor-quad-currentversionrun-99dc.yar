rule TTP_XOR_QUAD_CurrentVersionRun_99dc {
  strings:
    $key_99dc = { ca b3 [2] ee bd [2] c5 91 [2] eb b3 [2] ff a8 [2] f0 b2 [2] ee af [2] ec ae [2] f7 a8 [2] eb af [2] f7 80 }

  condition:
    any of them
}