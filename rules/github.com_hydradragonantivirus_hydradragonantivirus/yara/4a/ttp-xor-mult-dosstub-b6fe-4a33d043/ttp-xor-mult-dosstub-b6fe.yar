rule TTP_XOR_MULT_DOSStub_b6fe {
  strings:
    $key_b6fe = { e2 96 [2] 96 8e [2] d1 8c [2] 96 9d [2] d8 91 [2] d4 9b [2] c3 90 [2] d8 de [2] e5 }

  condition:
    any of them
}