rule TTP_XOR_MULT_DOSStub_db1d {
  strings:
    $key_db1d = { 8f 75 [2] fb 6d [2] bc 6f [2] fb 7e [2] b5 72 [2] b9 78 [2] ae 73 [2] b5 3d [2] 88 }

  condition:
    any of them
}