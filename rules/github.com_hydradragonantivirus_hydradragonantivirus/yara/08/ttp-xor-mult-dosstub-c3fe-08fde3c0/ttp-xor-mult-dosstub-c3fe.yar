rule TTP_XOR_MULT_DOSStub_c3fe {
  strings:
    $key_c3fe = { 97 96 [2] e3 8e [2] a4 8c [2] e3 9d [2] ad 91 [2] a1 9b [2] b6 90 [2] ad de [2] 90 }

  condition:
    any of them
}