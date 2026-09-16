rule TTP_XOR_QUAD_CurrentVersionRun_1ed2 {
  strings:
    $key_1ed2 = { 4d bd [2] 69 b3 [2] 42 9f [2] 6c bd [2] 78 a6 [2] 77 bc [2] 69 a1 [2] 6b a0 [2] 70 a6 [2] 6c a1 [2] 70 8e }

  condition:
    any of them
}