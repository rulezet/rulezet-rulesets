rule TTP_XOR_MULT_DOSStub_db8d {
  strings:
    $key_db8d = { 8f e5 [2] fb fd [2] bc ff [2] fb ee [2] b5 e2 [2] b9 e8 [2] ae e3 [2] b5 ad [2] 88 }

  condition:
    any of them
}