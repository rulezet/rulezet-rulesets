rule TTP_XOR_QUAD_CurrentVersionRun_acdc {
  strings:
    $key_acdc = { ff b3 [2] db bd [2] f0 91 [2] de b3 [2] ca a8 [2] c5 b2 [2] db af [2] d9 ae [2] c2 a8 [2] de af [2] c2 80 }

  condition:
    any of them
}