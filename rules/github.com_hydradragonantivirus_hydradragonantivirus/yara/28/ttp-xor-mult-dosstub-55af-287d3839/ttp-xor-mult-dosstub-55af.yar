rule TTP_XOR_MULT_DOSStub_55af {
  strings:
    $key_55af = { 01 c7 [2] 75 df [2] 32 dd [2] 75 cc [2] 3b c0 [2] 37 ca [2] 20 c1 [2] 3b 8f [2] 06 }

  condition:
    any of them
}