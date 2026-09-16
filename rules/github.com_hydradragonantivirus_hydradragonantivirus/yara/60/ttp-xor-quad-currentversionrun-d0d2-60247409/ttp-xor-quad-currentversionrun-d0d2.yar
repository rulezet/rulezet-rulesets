rule TTP_XOR_QUAD_CurrentVersionRun_d0d2 {
  strings:
    $key_d0d2 = { 83 bd [2] a7 b3 [2] 8c 9f [2] a2 bd [2] b6 a6 [2] b9 bc [2] a7 a1 [2] a5 a0 [2] be a6 [2] a2 a1 [2] be 8e }

  condition:
    any of them
}