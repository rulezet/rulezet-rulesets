rule TTP_XOR_MULT_DOSStub_40af {
  strings:
    $key_40af = { 14 c7 [2] 60 df [2] 27 dd [2] 60 cc [2] 2e c0 [2] 22 ca [2] 35 c1 [2] 2e 8f [2] 13 }

  condition:
    any of them
}