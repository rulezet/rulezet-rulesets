rule TTP_XOR_MULT_DOSStub_c1af {
  strings:
    $key_c1af = { 95 c7 [2] e1 df [2] a6 dd [2] e1 cc [2] af c0 [2] a3 ca [2] b4 c1 [2] af 8f [2] 92 }

  condition:
    any of them
}