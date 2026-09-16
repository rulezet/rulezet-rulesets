rule TTP_XOR_QUAD_CurrentVersionRun_e9d2 {
  strings:
    $key_e9d2 = { ba bd [2] 9e b3 [2] b5 9f [2] 9b bd [2] 8f a6 [2] 80 bc [2] 9e a1 [2] 9c a0 [2] 87 a6 [2] 9b a1 [2] 87 8e }

  condition:
    any of them
}