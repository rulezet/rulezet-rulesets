rule TTP_XOR_QUAD_CurrentVersionRun_e5d2 {
  strings:
    $key_e5d2 = { b6 bd [2] 92 b3 [2] b9 9f [2] 97 bd [2] 83 a6 [2] 8c bc [2] 92 a1 [2] 90 a0 [2] 8b a6 [2] 97 a1 [2] 8b 8e }

  condition:
    any of them
}