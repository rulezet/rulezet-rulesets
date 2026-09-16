rule TTP_XOR_QUAD_CurrentVersionRun_bcd8 {
  strings:
    $key_bcd8 = { ef b7 [2] cb b9 [2] e0 95 [2] ce b7 [2] da ac [2] d5 b6 [2] cb ab [2] c9 aa [2] d2 ac [2] ce ab [2] d2 84 }

  condition:
    any of them
}