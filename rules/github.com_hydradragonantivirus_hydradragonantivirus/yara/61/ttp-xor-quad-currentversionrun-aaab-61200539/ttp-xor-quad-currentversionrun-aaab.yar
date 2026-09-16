rule TTP_XOR_QUAD_CurrentVersionRun_aaab {
  strings:
    $key_aaab = { f9 c4 [2] dd ca [2] f6 e6 [2] d8 c4 [2] cc df [2] c3 c5 [2] dd d8 [2] df d9 [2] c4 df [2] d8 d8 [2] c4 f7 }

  condition:
    any of them
}