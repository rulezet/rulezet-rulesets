rule TTP_XOR_MULT_DOSStub_db3b {
  strings:
    $key_db3b = { 8f 53 [2] fb 4b [2] bc 49 [2] fb 58 [2] b5 54 [2] b9 5e [2] ae 55 [2] b5 1b [2] 88 }

  condition:
    any of them
}