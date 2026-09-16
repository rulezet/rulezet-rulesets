rule TTP_XOR_MULT_DOSStub_f5fe {
  strings:
    $key_f5fe = { a1 96 [2] d5 8e [2] 92 8c [2] d5 9d [2] 9b 91 [2] 97 9b [2] 80 90 [2] 9b de [2] a6 }

  condition:
    any of them
}