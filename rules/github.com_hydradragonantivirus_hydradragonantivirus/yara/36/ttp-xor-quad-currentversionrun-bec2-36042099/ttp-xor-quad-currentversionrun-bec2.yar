rule TTP_XOR_QUAD_CurrentVersionRun_bec2 {
  strings:
    $key_bec2 = { ed ad [2] c9 a3 [2] e2 8f [2] cc ad [2] d8 b6 [2] d7 ac [2] c9 b1 [2] cb b0 [2] d0 b6 [2] cc b1 [2] d0 9e }

  condition:
    any of them
}