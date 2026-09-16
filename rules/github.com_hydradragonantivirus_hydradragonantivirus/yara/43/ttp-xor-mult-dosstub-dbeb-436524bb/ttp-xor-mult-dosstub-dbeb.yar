rule TTP_XOR_MULT_DOSStub_dbeb {
  strings:
    $key_dbeb = { 8f 83 [2] fb 9b [2] bc 99 [2] fb 88 [2] b5 84 [2] b9 8e [2] ae 85 [2] b5 cb [2] 88 }

  condition:
    any of them
}