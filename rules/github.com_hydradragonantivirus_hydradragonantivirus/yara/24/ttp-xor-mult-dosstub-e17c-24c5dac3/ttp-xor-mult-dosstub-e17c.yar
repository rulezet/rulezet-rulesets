rule TTP_XOR_MULT_DOSStub_e17c {
  strings:
    $key_e17c = { b5 14 [2] c1 0c [2] 86 0e [2] c1 1f [2] 8f 13 [2] 83 19 [2] 94 12 [2] 8f 5c [2] b2 }

  condition:
    any of them
}