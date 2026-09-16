rule TTP_XOR_MULT_DOSStub_e2fe {
  strings:
    $key_e2fe = { b6 96 [2] c2 8e [2] 85 8c [2] c2 9d [2] 8c 91 [2] 80 9b [2] 97 90 [2] 8c de [2] b1 }

  condition:
    any of them
}