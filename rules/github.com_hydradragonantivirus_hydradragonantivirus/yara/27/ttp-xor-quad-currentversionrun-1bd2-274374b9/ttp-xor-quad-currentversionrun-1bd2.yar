rule TTP_XOR_QUAD_CurrentVersionRun_1bd2 {
  strings:
    $key_1bd2 = { 48 bd [2] 6c b3 [2] 47 9f [2] 69 bd [2] 7d a6 [2] 72 bc [2] 6c a1 [2] 6e a0 [2] 75 a6 [2] 69 a1 [2] 75 8e }

  condition:
    any of them
}