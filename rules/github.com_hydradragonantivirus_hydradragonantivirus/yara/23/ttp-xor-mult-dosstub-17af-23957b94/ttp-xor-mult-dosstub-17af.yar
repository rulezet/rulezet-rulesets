rule TTP_XOR_MULT_DOSStub_17af {
  strings:
    $key_17af = { 43 c7 [2] 37 df [2] 70 dd [2] 37 cc [2] 79 c0 [2] 75 ca [2] 62 c1 [2] 79 8f [2] 44 }

  condition:
    any of them
}