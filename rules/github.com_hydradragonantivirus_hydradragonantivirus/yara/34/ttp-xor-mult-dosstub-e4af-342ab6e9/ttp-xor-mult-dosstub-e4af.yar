rule TTP_XOR_MULT_DOSStub_e4af {
  strings:
    $key_e4af = { b0 c7 [2] c4 df [2] 83 dd [2] c4 cc [2] 8a c0 [2] 86 ca [2] 91 c1 [2] 8a 8f [2] b7 }

  condition:
    any of them
}