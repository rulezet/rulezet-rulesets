rule TTP_XOR_QUAD_CurrentVersionRun_c380 {
  strings:
    $key_c380 = { 90 ef [2] b4 e1 [2] 9f cd [2] b1 ef [2] a5 f4 [2] aa ee [2] b4 f3 [2] b6 f2 [2] ad f4 [2] b1 f3 [2] ad dc }

  condition:
    any of them
}