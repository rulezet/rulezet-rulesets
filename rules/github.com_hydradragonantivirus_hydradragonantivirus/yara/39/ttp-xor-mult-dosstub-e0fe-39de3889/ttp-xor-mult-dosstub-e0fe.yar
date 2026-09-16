rule TTP_XOR_MULT_DOSStub_e0fe {
  strings:
    $key_e0fe = { b4 96 [2] c0 8e [2] 87 8c [2] c0 9d [2] 8e 91 [2] 82 9b [2] 95 90 [2] 8e de [2] b3 }

  condition:
    any of them
}