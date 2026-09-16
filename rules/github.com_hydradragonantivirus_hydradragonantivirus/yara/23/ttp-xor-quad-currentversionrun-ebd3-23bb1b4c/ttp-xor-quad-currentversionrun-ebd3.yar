rule TTP_XOR_QUAD_CurrentVersionRun_ebd3 {
  strings:
    $key_ebd3 = { b8 bc [2] 9c b2 [2] b7 9e [2] 99 bc [2] 8d a7 [2] 82 bd [2] 9c a0 [2] 9e a1 [2] 85 a7 [2] 99 a0 [2] 85 8f }

  condition:
    any of them
}