rule TTP_XOR_QUAD_CurrentVersionRun_e5d0 {
  strings:
    $key_e5d0 = { b6 bf [2] 92 b1 [2] b9 9d [2] 97 bf [2] 83 a4 [2] 8c be [2] 92 a3 [2] 90 a2 [2] 8b a4 [2] 97 a3 [2] 8b 8c }

  condition:
    any of them
}