rule TTP_XOR_QUAD_CurrentVersionRun_c2c8 {
  strings:
    $key_c2c8 = { 91 a7 [2] b5 a9 [2] 9e 85 [2] b0 a7 [2] a4 bc [2] ab a6 [2] b5 bb [2] b7 ba [2] ac bc [2] b0 bb [2] ac 94 }

  condition:
    any of them
}