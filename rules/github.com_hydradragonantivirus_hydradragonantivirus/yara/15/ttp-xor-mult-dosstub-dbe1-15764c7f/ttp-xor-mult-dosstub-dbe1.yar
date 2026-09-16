rule TTP_XOR_MULT_DOSStub_dbe1 {
  strings:
    $key_dbe1 = { 8f 89 [2] fb 91 [2] bc 93 [2] fb 82 [2] b5 8e [2] b9 84 [2] ae 8f [2] b5 c1 [2] 88 }

  condition:
    any of them
}