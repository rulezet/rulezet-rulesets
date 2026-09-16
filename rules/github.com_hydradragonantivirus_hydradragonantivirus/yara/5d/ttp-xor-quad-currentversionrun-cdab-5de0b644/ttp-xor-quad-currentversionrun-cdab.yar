rule TTP_XOR_QUAD_CurrentVersionRun_cdab {
  strings:
    $key_cdab = { 9e c4 [2] ba ca [2] 91 e6 [2] bf c4 [2] ab df [2] a4 c5 [2] ba d8 [2] b8 d9 [2] a3 df [2] bf d8 [2] a3 f7 }

  condition:
    any of them
}