rule TTP_XOR_MULT_DOSStub_db03 {
  strings:
    $key_db03 = { 8f 6b [2] fb 73 [2] bc 71 [2] fb 60 [2] b5 6c [2] b9 66 [2] ae 6d [2] b5 23 [2] 88 }

  condition:
    any of them
}