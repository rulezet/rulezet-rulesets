rule TTP_XOR_MULT_DOSStub_0be3 {
  strings:
    $key_0be3 = { 5f 8b [2] 2b 93 [2] 6c 91 [2] 2b 80 [2] 65 8c [2] 69 86 [2] 7e 8d [2] 65 c3 [2] 58 }

  condition:
    any of them
}