rule TTP_XOR_MULT_DOSStub_56af {
  strings:
    $key_56af = { 02 c7 [2] 76 df [2] 31 dd [2] 76 cc [2] 38 c0 [2] 34 ca [2] 23 c1 [2] 38 8f [2] 05 }

  condition:
    any of them
}