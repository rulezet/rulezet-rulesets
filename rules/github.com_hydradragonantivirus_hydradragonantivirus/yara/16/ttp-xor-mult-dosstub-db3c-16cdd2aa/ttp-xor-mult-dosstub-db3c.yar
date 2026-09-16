rule TTP_XOR_MULT_DOSStub_db3c {
  strings:
    $key_db3c = { 8f 54 [2] fb 4c [2] bc 4e [2] fb 5f [2] b5 53 [2] b9 59 [2] ae 52 [2] b5 1c [2] 88 }

  condition:
    any of them
}