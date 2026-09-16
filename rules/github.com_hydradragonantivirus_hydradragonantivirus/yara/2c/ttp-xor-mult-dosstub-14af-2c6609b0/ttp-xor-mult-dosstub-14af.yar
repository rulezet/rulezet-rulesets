rule TTP_XOR_MULT_DOSStub_14af {
  strings:
    $key_14af = { 40 c7 [2] 34 df [2] 73 dd [2] 34 cc [2] 7a c0 [2] 76 ca [2] 61 c1 [2] 7a 8f [2] 47 }

  condition:
    any of them
}