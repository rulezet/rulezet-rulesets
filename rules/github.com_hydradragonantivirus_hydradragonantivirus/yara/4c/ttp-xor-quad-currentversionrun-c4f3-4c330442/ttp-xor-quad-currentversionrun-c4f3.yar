rule TTP_XOR_QUAD_CurrentVersionRun_c4f3 {
  strings:
    $key_c4f3 = { 97 9c [2] b3 92 [2] 98 be [2] b6 9c [2] a2 87 [2] ad 9d [2] b3 80 [2] b1 81 [2] aa 87 [2] b6 80 [2] aa af }

  condition:
    any of them
}