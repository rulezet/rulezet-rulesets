rule TTP_XOR_QUAD_CurrentVersionRun_61d2 {
  strings:
    $key_61d2 = { 32 bd [2] 16 b3 [2] 3d 9f [2] 13 bd [2] 07 a6 [2] 08 bc [2] 16 a1 [2] 14 a0 [2] 0f a6 [2] 13 a1 [2] 0f 8e }

  condition:
    any of them
}