rule TTP_XOR_MULT_DOSStub_db1e {
  strings:
    $key_db1e = { 8f 76 [2] fb 6e [2] bc 6c [2] fb 7d [2] b5 71 [2] b9 7b [2] ae 70 [2] b5 3e [2] 88 }

  condition:
    any of them
}