rule TTP_XOR_MULT_DOSStub_e04c {
  strings:
    $key_e04c = { b4 24 [2] c0 3c [2] 87 3e [2] c0 2f [2] 8e 23 [2] 82 29 [2] 95 22 [2] 8e 6c [2] b3 }

  condition:
    any of them
}