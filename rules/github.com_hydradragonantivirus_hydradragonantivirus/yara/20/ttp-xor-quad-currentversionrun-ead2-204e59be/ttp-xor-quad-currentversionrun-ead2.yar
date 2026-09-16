rule TTP_XOR_QUAD_CurrentVersionRun_ead2 {
  strings:
    $key_ead2 = { b9 bd [2] 9d b3 [2] b6 9f [2] 98 bd [2] 8c a6 [2] 83 bc [2] 9d a1 [2] 9f a0 [2] 84 a6 [2] 98 a1 [2] 84 8e }

  condition:
    any of them
}