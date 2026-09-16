rule TTP_XOR_MULT_DOSStub_e7fe {
  strings:
    $key_e7fe = { b3 96 [2] c7 8e [2] 80 8c [2] c7 9d [2] 89 91 [2] 85 9b [2] 92 90 [2] 89 de [2] b4 }

  condition:
    any of them
}