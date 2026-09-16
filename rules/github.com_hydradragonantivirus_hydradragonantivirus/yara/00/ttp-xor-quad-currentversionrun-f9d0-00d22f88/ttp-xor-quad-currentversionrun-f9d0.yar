rule TTP_XOR_QUAD_CurrentVersionRun_f9d0 {
  strings:
    $key_f9d0 = { aa bf [2] 8e b1 [2] a5 9d [2] 8b bf [2] 9f a4 [2] 90 be [2] 8e a3 [2] 8c a2 [2] 97 a4 [2] 8b a3 [2] 97 8c }

  condition:
    any of them
}