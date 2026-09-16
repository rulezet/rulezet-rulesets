rule TTP_XOR_QUAD_CurrentVersionRun_c491 {
  strings:
    $key_c491 = { 97 fe [2] b3 f0 [2] 98 dc [2] b6 fe [2] a2 e5 [2] ad ff [2] b3 e2 [2] b1 e3 [2] aa e5 [2] b6 e2 [2] aa cd }

  condition:
    any of them
}