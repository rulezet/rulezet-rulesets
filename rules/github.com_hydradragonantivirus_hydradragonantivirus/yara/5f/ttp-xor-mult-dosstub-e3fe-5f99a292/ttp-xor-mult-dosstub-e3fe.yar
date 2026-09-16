rule TTP_XOR_MULT_DOSStub_e3fe {
  strings:
    $key_e3fe = { b7 96 [2] c3 8e [2] 84 8c [2] c3 9d [2] 8d 91 [2] 81 9b [2] 96 90 [2] 8d de [2] b0 }

  condition:
    any of them
}