rule TTP_XOR_MULT_DOSStub_5eaf {
  strings:
    $key_5eaf = { 0a c7 [2] 7e df [2] 39 dd [2] 7e cc [2] 30 c0 [2] 3c ca [2] 2b c1 [2] 30 8f [2] 0d }

  condition:
    any of them
}