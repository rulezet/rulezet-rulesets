rule TTP_XOR_MULT_DOSStub_db0b {
  strings:
    $key_db0b = { 8f 63 [2] fb 7b [2] bc 79 [2] fb 68 [2] b5 64 [2] b9 6e [2] ae 65 [2] b5 2b [2] 88 }

  condition:
    any of them
}