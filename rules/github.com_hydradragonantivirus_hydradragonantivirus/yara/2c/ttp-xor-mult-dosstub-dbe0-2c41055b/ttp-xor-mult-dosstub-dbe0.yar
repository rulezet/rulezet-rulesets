rule TTP_XOR_MULT_DOSStub_dbe0 {
  strings:
    $key_dbe0 = { 8f 88 [2] fb 90 [2] bc 92 [2] fb 83 [2] b5 8f [2] b9 85 [2] ae 8e [2] b5 c0 [2] 88 }

  condition:
    any of them
}