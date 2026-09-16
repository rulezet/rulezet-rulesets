rule TTP_XOR_MULT_DOSStub_f6fe {
  strings:
    $key_f6fe = { a2 96 [2] d6 8e [2] 91 8c [2] d6 9d [2] 98 91 [2] 94 9b [2] 83 90 [2] 98 de [2] a5 }

  condition:
    any of them
}