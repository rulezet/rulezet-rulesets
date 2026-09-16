rule TTP_XOR_MULT_DOSStub_f4fe {
  strings:
    $key_f4fe = { a0 96 [2] d4 8e [2] 93 8c [2] d4 9d [2] 9a 91 [2] 96 9b [2] 81 90 [2] 9a de [2] a7 }

  condition:
    any of them
}