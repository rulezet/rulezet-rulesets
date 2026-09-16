rule TTP_XOR_MULT_DOSStub_25af {
  strings:
    $key_25af = { 71 c7 [2] 05 df [2] 42 dd [2] 05 cc [2] 4b c0 [2] 47 ca [2] 50 c1 [2] 4b 8f [2] 76 }

  condition:
    any of them
}