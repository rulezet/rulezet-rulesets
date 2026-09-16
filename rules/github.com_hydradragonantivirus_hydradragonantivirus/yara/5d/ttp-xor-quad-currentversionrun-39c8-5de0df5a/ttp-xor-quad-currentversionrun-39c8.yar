rule TTP_XOR_QUAD_CurrentVersionRun_39c8 {
  strings:
    $key_39c8 = { 6a a7 [2] 4e a9 [2] 65 85 [2] 4b a7 [2] 5f bc [2] 50 a6 [2] 4e bb [2] 4c ba [2] 57 bc [2] 4b bb [2] 57 94 }

  condition:
    any of them
}