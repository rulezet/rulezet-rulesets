rule TTP_XOR_QUAD_CurrentVersionRun_ebd2 {
  strings:
    $key_ebd2 = { b8 bd [2] 9c b3 [2] b7 9f [2] 99 bd [2] 8d a6 [2] 82 bc [2] 9c a1 [2] 9e a0 [2] 85 a6 [2] 99 a1 [2] 85 8e }

  condition:
    any of them
}