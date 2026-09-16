rule TTP_XOR_MULT_DOSStub_dbfd {
  strings:
    $key_dbfd = { 8f 95 [2] fb 8d [2] bc 8f [2] fb 9e [2] b5 92 [2] b9 98 [2] ae 93 [2] b5 dd [2] 88 }

  condition:
    any of them
}