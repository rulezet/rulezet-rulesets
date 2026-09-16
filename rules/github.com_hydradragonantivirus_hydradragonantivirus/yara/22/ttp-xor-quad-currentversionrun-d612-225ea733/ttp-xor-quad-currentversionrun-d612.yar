rule TTP_XOR_QUAD_CurrentVersionRun_d612 {
  strings:
    $key_d612 = { 85 7d [2] a1 73 [2] 8a 5f [2] a4 7d [2] b0 66 [2] bf 7c [2] a1 61 [2] a3 60 [2] b8 66 [2] a4 61 [2] b8 4e }

  condition:
    any of them
}