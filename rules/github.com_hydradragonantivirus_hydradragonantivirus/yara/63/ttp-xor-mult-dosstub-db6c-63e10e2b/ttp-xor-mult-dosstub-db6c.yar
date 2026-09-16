rule TTP_XOR_MULT_DOSStub_db6c {
  strings:
    $key_db6c = { 8f 04 [2] fb 1c [2] bc 1e [2] fb 0f [2] b5 03 [2] b9 09 [2] ae 02 [2] b5 4c [2] 88 }

  condition:
    any of them
}