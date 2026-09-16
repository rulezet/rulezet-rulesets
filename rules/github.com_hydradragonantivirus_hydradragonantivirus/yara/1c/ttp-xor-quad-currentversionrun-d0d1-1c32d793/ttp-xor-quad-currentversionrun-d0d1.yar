rule TTP_XOR_QUAD_CurrentVersionRun_d0d1 {
  strings:
    $key_d0d1 = { 83 be [2] a7 b0 [2] 8c 9c [2] a2 be [2] b6 a5 [2] b9 bf [2] a7 a2 [2] a5 a3 [2] be a5 [2] a2 a2 [2] be 8d }

  condition:
    any of them
}