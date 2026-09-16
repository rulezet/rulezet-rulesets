rule TTP_XOR_MULT_DOSStub_db0f {
  strings:
    $key_db0f = { 8f 67 [2] fb 7f [2] bc 7d [2] fb 6c [2] b5 60 [2] b9 6a [2] ae 61 [2] b5 2f [2] 88 }

  condition:
    any of them
}