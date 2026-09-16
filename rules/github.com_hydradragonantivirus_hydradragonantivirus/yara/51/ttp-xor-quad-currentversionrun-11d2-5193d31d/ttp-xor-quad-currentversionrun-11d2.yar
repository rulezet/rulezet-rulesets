rule TTP_XOR_QUAD_CurrentVersionRun_11d2 {
  strings:
    $key_11d2 = { 42 bd [2] 66 b3 [2] 4d 9f [2] 63 bd [2] 77 a6 [2] 78 bc [2] 66 a1 [2] 64 a0 [2] 7f a6 [2] 63 a1 [2] 7f 8e }

  condition:
    any of them
}