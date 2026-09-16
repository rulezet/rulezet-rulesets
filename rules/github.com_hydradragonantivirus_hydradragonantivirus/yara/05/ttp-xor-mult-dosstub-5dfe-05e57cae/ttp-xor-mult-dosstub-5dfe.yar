rule TTP_XOR_MULT_DOSStub_5dfe {
  strings:
    $key_5dfe = { 09 96 [2] 7d 8e [2] 3a 8c [2] 7d 9d [2] 33 91 [2] 3f 9b [2] 28 90 [2] 33 de [2] 0e }

  condition:
    any of them
}