rule TTP_XOR_MULT_DOSStub_db5e {
  strings:
    $key_db5e = { 8f 36 [2] fb 2e [2] bc 2c [2] fb 3d [2] b5 31 [2] b9 3b [2] ae 30 [2] b5 7e [2] 88 }

  condition:
    any of them
}