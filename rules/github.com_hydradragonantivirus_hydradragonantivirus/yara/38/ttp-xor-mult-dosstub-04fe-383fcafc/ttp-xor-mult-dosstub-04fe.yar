rule TTP_XOR_MULT_DOSStub_04fe {
  strings:
    $key_04fe = { 50 96 [2] 24 8e [2] 63 8c [2] 24 9d [2] 6a 91 [2] 66 9b [2] 71 90 [2] 6a de [2] 57 }

  condition:
    any of them
}