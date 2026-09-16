rule TTP_XOR_QUAD_CurrentVersionRun_3ed2 {
  strings:
    $key_3ed2 = { 6d bd [2] 49 b3 [2] 62 9f [2] 4c bd [2] 58 a6 [2] 57 bc [2] 49 a1 [2] 4b a0 [2] 50 a6 [2] 4c a1 [2] 50 8e }

  condition:
    any of them
}