rule TTP_XOR_MULT_DOSStub_e11c {
  strings:
    $key_e11c = { b5 74 [2] c1 6c [2] 86 6e [2] c1 7f [2] 8f 73 [2] 83 79 [2] 94 72 [2] 8f 3c [2] b2 }

  condition:
    any of them
}