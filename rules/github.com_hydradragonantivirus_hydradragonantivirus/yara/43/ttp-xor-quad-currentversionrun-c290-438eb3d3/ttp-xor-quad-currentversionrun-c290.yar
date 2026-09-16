rule TTP_XOR_QUAD_CurrentVersionRun_c290 {
  strings:
    $key_c290 = { 91 ff [2] b5 f1 [2] 9e dd [2] b0 ff [2] a4 e4 [2] ab fe [2] b5 e3 [2] b7 e2 [2] ac e4 [2] b0 e3 [2] ac cc }

  condition:
    any of them
}