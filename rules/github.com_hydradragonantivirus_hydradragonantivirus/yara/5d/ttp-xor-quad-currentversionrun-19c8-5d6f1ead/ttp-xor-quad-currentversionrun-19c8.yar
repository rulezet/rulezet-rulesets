rule TTP_XOR_QUAD_CurrentVersionRun_19c8 {
  strings:
    $key_19c8 = { 4a a7 [2] 6e a9 [2] 45 85 [2] 6b a7 [2] 7f bc [2] 70 a6 [2] 6e bb [2] 6c ba [2] 77 bc [2] 6b bb [2] 77 94 }

  condition:
    any of them
}