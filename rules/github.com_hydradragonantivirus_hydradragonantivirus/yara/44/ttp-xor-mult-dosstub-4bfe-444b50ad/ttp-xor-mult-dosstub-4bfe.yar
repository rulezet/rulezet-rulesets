rule TTP_XOR_MULT_DOSStub_4bfe {
  strings:
    $key_4bfe = { 1f 96 [2] 6b 8e [2] 2c 8c [2] 6b 9d [2] 25 91 [2] 29 9b [2] 3e 90 [2] 25 de [2] 18 }

  condition:
    any of them
}