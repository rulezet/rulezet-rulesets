rule TTP_XOR_MULT_DOSStub_dbef {
  strings:
    $key_dbef = { 8f 87 [2] fb 9f [2] bc 9d [2] fb 8c [2] b5 80 [2] b9 8a [2] ae 81 [2] b5 cf [2] 88 }

  condition:
    any of them
}