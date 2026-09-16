rule TTP_XOR_MULT_DOSStub_eeaf {
  strings:
    $key_eeaf = { ba c7 [2] ce df [2] 89 dd [2] ce cc [2] 80 c0 [2] 8c ca [2] 9b c1 [2] 80 8f [2] bd }

  condition:
    any of them
}