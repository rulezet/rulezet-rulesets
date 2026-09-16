rule TTP_XOR_QUAD_CurrentVersionRun_dcd9 {
  strings:
    $key_dcd9 = { 8f b6 [2] ab b8 [2] 80 94 [2] ae b6 [2] ba ad [2] b5 b7 [2] ab aa [2] a9 ab [2] b2 ad [2] ae aa [2] b2 85 }

  condition:
    any of them
}