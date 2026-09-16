rule TTP_XOR_MULT_DOSStub_64fe {
  strings:
    $key_64fe = { 30 96 [2] 44 8e [2] 03 8c [2] 44 9d [2] 0a 91 [2] 06 9b [2] 11 90 [2] 0a de [2] 37 }

  condition:
    any of them
}