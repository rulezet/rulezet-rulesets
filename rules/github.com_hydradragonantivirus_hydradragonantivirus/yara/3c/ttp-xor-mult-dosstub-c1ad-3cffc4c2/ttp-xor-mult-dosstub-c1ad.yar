rule TTP_XOR_MULT_DOSStub_c1ad {
  strings:
    $key_c1ad = { 95 c5 [2] e1 dd [2] a6 df [2] e1 ce [2] af c2 [2] a3 c8 [2] b4 c3 [2] af 8d [2] 92 }

  condition:
    any of them
}