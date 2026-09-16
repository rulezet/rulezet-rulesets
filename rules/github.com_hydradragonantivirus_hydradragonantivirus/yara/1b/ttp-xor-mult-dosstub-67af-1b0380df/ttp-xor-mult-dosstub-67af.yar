rule TTP_XOR_MULT_DOSStub_67af {
  strings:
    $key_67af = { 33 c7 [2] 47 df [2] 00 dd [2] 47 cc [2] 09 c0 [2] 05 ca [2] 12 c1 [2] 09 8f [2] 34 }

  condition:
    any of them
}