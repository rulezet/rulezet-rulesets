rule TTP_XOR_QUAD_CurrentVersionRun_dcdc {
  strings:
    $key_dcdc = { 8f b3 [2] ab bd [2] 80 91 [2] ae b3 [2] ba a8 [2] b5 b2 [2] ab af [2] a9 ae [2] b2 a8 [2] ae af [2] b2 80 }

  condition:
    any of them
}