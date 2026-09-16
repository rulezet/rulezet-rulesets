rule TTP_XOR_MULT_DOSStub_c7af {
  strings:
    $key_c7af = { 93 c7 [2] e7 df [2] a0 dd [2] e7 cc [2] a9 c0 [2] a5 ca [2] b2 c1 [2] a9 8f [2] 94 }

  condition:
    any of them
}