rule TTP_XOR_QUAD_CurrentVersionRun_cda8 {
  strings:
    $key_cda8 = { 9e c7 [2] ba c9 [2] 91 e5 [2] bf c7 [2] ab dc [2] a4 c6 [2] ba db [2] b8 da [2] a3 dc [2] bf db [2] a3 f4 }

  condition:
    any of them
}