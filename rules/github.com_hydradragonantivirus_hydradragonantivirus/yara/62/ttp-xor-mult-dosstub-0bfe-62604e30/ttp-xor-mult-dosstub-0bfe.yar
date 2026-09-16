rule TTP_XOR_MULT_DOSStub_0bfe {
  strings:
    $key_0bfe = { 5f 96 [2] 2b 8e [2] 6c 8c [2] 2b 9d [2] 65 91 [2] 69 9b [2] 7e 90 [2] 65 de [2] 58 }

  condition:
    any of them
}