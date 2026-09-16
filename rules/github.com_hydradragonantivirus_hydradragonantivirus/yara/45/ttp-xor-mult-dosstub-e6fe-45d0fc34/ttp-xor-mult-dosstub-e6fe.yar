rule TTP_XOR_MULT_DOSStub_e6fe {
  strings:
    $key_e6fe = { b2 96 [2] c6 8e [2] 81 8c [2] c6 9d [2] 88 91 [2] 84 9b [2] 93 90 [2] 88 de [2] b5 }

  condition:
    any of them
}