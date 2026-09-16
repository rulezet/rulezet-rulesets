rule TTP_XOR_QUAD_CurrentVersionRun_09d2 {
  strings:
    $key_09d2 = { 5a bd [2] 7e b3 [2] 55 9f [2] 7b bd [2] 6f a6 [2] 60 bc [2] 7e a1 [2] 7c a0 [2] 67 a6 [2] 7b a1 [2] 67 8e }

  condition:
    any of them
}