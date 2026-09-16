rule TTP_XOR_MULT_DOSStub_c3af {
  strings:
    $key_c3af = { 97 c7 [2] e3 df [2] a4 dd [2] e3 cc [2] ad c0 [2] a1 ca [2] b6 c1 [2] ad 8f [2] 90 }

  condition:
    any of them
}