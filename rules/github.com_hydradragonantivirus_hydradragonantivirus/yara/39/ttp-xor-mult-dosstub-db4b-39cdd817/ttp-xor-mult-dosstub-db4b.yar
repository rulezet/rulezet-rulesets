rule TTP_XOR_MULT_DOSStub_db4b {
  strings:
    $key_db4b = { 8f 23 [2] fb 3b [2] bc 39 [2] fb 28 [2] b5 24 [2] b9 2e [2] ae 25 [2] b5 6b [2] 88 }

  condition:
    any of them
}