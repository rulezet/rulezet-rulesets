rule TTP_XOR_MULT_DOSStub_4eaf {
  strings:
    $key_4eaf = { 1a c7 [2] 6e df [2] 29 dd [2] 6e cc [2] 20 c0 [2] 2c ca [2] 3b c1 [2] 20 8f [2] 1d }

  condition:
    any of them
}