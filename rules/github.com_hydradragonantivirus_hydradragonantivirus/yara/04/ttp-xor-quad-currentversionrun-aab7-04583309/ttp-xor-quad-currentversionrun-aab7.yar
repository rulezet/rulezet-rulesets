rule TTP_XOR_QUAD_CurrentVersionRun_aab7 {
  strings:
    $key_aab7 = { f9 d8 [2] dd d6 [2] f6 fa [2] d8 d8 [2] cc c3 [2] c3 d9 [2] dd c4 [2] df c5 [2] c4 c3 [2] d8 c4 [2] c4 eb }

  condition:
    any of them
}