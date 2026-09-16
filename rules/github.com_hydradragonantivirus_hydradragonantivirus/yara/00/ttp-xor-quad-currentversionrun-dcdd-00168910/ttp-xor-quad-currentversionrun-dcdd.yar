rule TTP_XOR_QUAD_CurrentVersionRun_dcdd {
  strings:
    $key_dcdd = { 8f b2 [2] ab bc [2] 80 90 [2] ae b2 [2] ba a9 [2] b5 b3 [2] ab ae [2] a9 af [2] b2 a9 [2] ae ae [2] b2 81 }

  condition:
    any of them
}