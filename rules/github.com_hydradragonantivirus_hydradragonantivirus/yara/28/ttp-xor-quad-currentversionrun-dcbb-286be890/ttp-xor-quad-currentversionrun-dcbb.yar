rule TTP_XOR_QUAD_CurrentVersionRun_dcbb {
  strings:
    $key_dcbb = { 8f d4 [2] ab da [2] 80 f6 [2] ae d4 [2] ba cf [2] b5 d5 [2] ab c8 [2] a9 c9 [2] b2 cf [2] ae c8 [2] b2 e7 }

  condition:
    any of them
}