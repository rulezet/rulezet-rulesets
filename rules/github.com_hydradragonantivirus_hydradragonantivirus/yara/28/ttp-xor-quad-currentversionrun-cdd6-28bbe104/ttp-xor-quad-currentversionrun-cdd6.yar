rule TTP_XOR_QUAD_CurrentVersionRun_cdd6 {
  strings:
    $key_cdd6 = { 9e b9 [2] ba b7 [2] 91 9b [2] bf b9 [2] ab a2 [2] a4 b8 [2] ba a5 [2] b8 a4 [2] a3 a2 [2] bf a5 [2] a3 8a }

  condition:
    any of them
}