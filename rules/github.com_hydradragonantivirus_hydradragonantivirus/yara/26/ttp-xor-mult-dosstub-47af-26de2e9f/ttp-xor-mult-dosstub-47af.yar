rule TTP_XOR_MULT_DOSStub_47af {
  strings:
    $key_47af = { 13 c7 [2] 67 df [2] 20 dd [2] 67 cc [2] 29 c0 [2] 25 ca [2] 32 c1 [2] 29 8f [2] 14 }

  condition:
    any of them
}