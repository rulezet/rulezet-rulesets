rule TTP_XOR_QUAD_CurrentVersionRun_aec2 {
  strings:
    $key_aec2 = { fd ad [2] d9 a3 [2] f2 8f [2] dc ad [2] c8 b6 [2] c7 ac [2] d9 b1 [2] db b0 [2] c0 b6 [2] dc b1 [2] c0 9e }

  condition:
    any of them
}