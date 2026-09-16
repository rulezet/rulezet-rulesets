rule TTP_XOR_MULT_DOSStub_b7fe {
  strings:
    $key_b7fe = { e3 96 [2] 97 8e [2] d0 8c [2] 97 9d [2] d9 91 [2] d5 9b [2] c2 90 [2] d9 de [2] e4 }

  condition:
    any of them
}