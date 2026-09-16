rule TTP_XOR_QUAD_CurrentVersionRun_98dc {
  strings:
    $key_98dc = { cb b3 [2] ef bd [2] c4 91 [2] ea b3 [2] fe a8 [2] f1 b2 [2] ef af [2] ed ae [2] f6 a8 [2] ea af [2] f6 80 }

  condition:
    any of them
}