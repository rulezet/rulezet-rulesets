rule TTP_XOR_MULT_DOSStub_dbff {
  strings:
    $key_dbff = { 8f 97 [2] fb 8f [2] bc 8d [2] fb 9c [2] b5 90 [2] b9 9a [2] ae 91 [2] b5 df [2] 88 }

  condition:
    any of them
}