rule TTP_XOR_QUAD_CurrentVersionRun_09c8 {
  strings:
    $key_09c8 = { 5a a7 [2] 7e a9 [2] 55 85 [2] 7b a7 [2] 6f bc [2] 60 a6 [2] 7e bb [2] 7c ba [2] 67 bc [2] 7b bb [2] 67 94 }

  condition:
    any of them
}