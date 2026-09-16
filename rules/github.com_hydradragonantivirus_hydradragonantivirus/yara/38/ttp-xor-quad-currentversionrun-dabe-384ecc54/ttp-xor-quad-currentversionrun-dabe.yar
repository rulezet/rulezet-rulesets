rule TTP_XOR_QUAD_CurrentVersionRun_dabe {
  strings:
    $key_dabe = { 89 d1 [2] ad df [2] 86 f3 [2] a8 d1 [2] bc ca [2] b3 d0 [2] ad cd [2] af cc [2] b4 ca [2] a8 cd [2] b4 e2 }

  condition:
    any of them
}