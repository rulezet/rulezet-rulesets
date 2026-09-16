rule TTP_XOR_QUAD_CurrentVersionRun_01d2 {
  strings:
    $key_01d2 = { 52 bd [2] 76 b3 [2] 5d 9f [2] 73 bd [2] 67 a6 [2] 68 bc [2] 76 a1 [2] 74 a0 [2] 6f a6 [2] 73 a1 [2] 6f 8e }

  condition:
    any of them
}