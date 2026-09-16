rule TTP_XOR_QUAD_CurrentVersionRun_38d2 {
  strings:
    $key_38d2 = { 6b bd [2] 4f b3 [2] 64 9f [2] 4a bd [2] 5e a6 [2] 51 bc [2] 4f a1 [2] 4d a0 [2] 56 a6 [2] 4a a1 [2] 56 8e }

  condition:
    any of them
}