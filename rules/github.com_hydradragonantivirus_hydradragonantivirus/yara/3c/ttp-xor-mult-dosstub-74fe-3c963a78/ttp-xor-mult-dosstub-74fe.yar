rule TTP_XOR_MULT_DOSStub_74fe {
  strings:
    $key_74fe = { 20 96 [2] 54 8e [2] 13 8c [2] 54 9d [2] 1a 91 [2] 16 9b [2] 01 90 [2] 1a de [2] 27 }

  condition:
    any of them
}