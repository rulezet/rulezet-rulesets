rule TTP_XOR_MULT_DOSStub_1cfe {
  strings:
    $key_1cfe = { 48 96 [2] 3c 8e [2] 7b 8c [2] 3c 9d [2] 72 91 [2] 7e 9b [2] 69 90 [2] 72 de [2] 4f }

  condition:
    any of them
}