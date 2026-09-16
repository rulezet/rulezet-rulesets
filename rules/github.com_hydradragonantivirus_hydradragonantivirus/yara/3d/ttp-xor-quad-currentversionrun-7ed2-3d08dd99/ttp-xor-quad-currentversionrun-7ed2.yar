rule TTP_XOR_QUAD_CurrentVersionRun_7ed2 {
  strings:
    $key_7ed2 = { 2d bd [2] 09 b3 [2] 22 9f [2] 0c bd [2] 18 a6 [2] 17 bc [2] 09 a1 [2] 0b a0 [2] 10 a6 [2] 0c a1 [2] 10 8e }

  condition:
    any of them
}