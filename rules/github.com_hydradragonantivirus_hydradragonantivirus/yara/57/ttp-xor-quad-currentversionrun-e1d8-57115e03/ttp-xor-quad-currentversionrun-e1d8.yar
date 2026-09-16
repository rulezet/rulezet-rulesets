rule TTP_XOR_QUAD_CurrentVersionRun_e1d8 {
  strings:
    $key_e1d8 = { b2 b7 [2] 96 b9 [2] bd 95 [2] 93 b7 [2] 87 ac [2] 88 b6 [2] 96 ab [2] 94 aa [2] 8f ac [2] 93 ab [2] 8f 84 }

  condition:
    any of them
}