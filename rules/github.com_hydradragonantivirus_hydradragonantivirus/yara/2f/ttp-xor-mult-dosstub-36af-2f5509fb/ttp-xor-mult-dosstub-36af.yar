rule TTP_XOR_MULT_DOSStub_36af {
  strings:
    $key_36af = { 62 c7 [2] 16 df [2] 51 dd [2] 16 cc [2] 58 c0 [2] 54 ca [2] 43 c1 [2] 58 8f [2] 65 }

  condition:
    any of them
}