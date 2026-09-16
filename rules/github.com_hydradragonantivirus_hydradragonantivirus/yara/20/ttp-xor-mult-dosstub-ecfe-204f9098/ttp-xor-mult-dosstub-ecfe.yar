rule TTP_XOR_MULT_DOSStub_ecfe {
  strings:
    $key_ecfe = { b8 96 [2] cc 8e [2] 8b 8c [2] cc 9d [2] 82 91 [2] 8e 9b [2] 99 90 [2] 82 de [2] bf }

  condition:
    any of them
}