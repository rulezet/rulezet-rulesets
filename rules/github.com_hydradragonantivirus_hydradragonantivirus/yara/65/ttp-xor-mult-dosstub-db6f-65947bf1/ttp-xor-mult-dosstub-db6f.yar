rule TTP_XOR_MULT_DOSStub_db6f {
  strings:
    $key_db6f = { 8f 07 [2] fb 1f [2] bc 1d [2] fb 0c [2] b5 00 [2] b9 0a [2] ae 01 [2] b5 4f [2] 88 }

  condition:
    any of them
}