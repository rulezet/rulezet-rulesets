rule TTP_XOR_MULT_DOSStub_db0e {
  strings:
    $key_db0e = { 8f 66 [2] fb 7e [2] bc 7c [2] fb 6d [2] b5 61 [2] b9 6b [2] ae 60 [2] b5 2e [2] 88 }

  condition:
    any of them
}