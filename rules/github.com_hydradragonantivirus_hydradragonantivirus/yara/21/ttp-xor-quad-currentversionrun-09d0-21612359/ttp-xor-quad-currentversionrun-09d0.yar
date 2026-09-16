rule TTP_XOR_QUAD_CurrentVersionRun_09d0 {
  strings:
    $key_09d0 = { 5a bf [2] 7e b1 [2] 55 9d [2] 7b bf [2] 6f a4 [2] 60 be [2] 7e a3 [2] 7c a2 [2] 67 a4 [2] 7b a3 [2] 67 8c }

  condition:
    any of them
}