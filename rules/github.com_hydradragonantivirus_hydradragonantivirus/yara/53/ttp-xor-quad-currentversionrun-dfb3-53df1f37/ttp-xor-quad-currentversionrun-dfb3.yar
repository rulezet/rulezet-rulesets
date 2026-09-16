rule TTP_XOR_QUAD_CurrentVersionRun_dfb3 {
  strings:
    $key_dfb3 = { 8c dc [2] a8 d2 [2] 83 fe [2] ad dc [2] b9 c7 [2] b6 dd [2] a8 c0 [2] aa c1 [2] b1 c7 [2] ad c0 [2] b1 ef }

  condition:
    any of them
}