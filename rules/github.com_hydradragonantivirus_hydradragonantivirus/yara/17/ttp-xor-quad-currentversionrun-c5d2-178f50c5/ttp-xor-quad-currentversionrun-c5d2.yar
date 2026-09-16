rule TTP_XOR_QUAD_CurrentVersionRun_c5d2 {
  strings:
    $key_c5d2 = { 96 bd [2] b2 b3 [2] 99 9f [2] b7 bd [2] a3 a6 [2] ac bc [2] b2 a1 [2] b0 a0 [2] ab a6 [2] b7 a1 [2] ab 8e }

  condition:
    any of them
}