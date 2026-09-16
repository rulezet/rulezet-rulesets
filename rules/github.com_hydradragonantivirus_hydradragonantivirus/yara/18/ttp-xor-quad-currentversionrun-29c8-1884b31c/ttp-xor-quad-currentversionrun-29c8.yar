rule TTP_XOR_QUAD_CurrentVersionRun_29c8 {
  strings:
    $key_29c8 = { 7a a7 [2] 5e a9 [2] 75 85 [2] 5b a7 [2] 4f bc [2] 40 a6 [2] 5e bb [2] 5c ba [2] 47 bc [2] 5b bb [2] 47 94 }

  condition:
    any of them
}