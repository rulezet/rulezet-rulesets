rule TTP_XOR_MULT_DOSStub_3eaf {
  strings:
    $key_3eaf = { 6a c7 [2] 1e df [2] 59 dd [2] 1e cc [2] 50 c0 [2] 5c ca [2] 4b c1 [2] 50 8f [2] 6d }

  condition:
    any of them
}