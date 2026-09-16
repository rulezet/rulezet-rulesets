rule TTP_XOR_MULT_DOSStub_1bfe {
  strings:
    $key_1bfe = { 4f 96 [2] 3b 8e [2] 7c 8c [2] 3b 9d [2] 75 91 [2] 79 9b [2] 6e 90 [2] 75 de [2] 48 }

  condition:
    any of them
}