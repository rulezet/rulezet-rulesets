rule TTP_XOR_MULT_DOSStub_db0c {
  strings:
    $key_db0c = { 8f 64 [2] fb 7c [2] bc 7e [2] fb 6f [2] b5 63 [2] b9 69 [2] ae 62 [2] b5 2c [2] 88 }

  condition:
    any of them
}