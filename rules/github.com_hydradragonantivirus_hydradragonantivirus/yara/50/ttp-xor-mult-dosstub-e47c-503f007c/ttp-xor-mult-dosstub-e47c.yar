rule TTP_XOR_MULT_DOSStub_e47c {
  strings:
    $key_e47c = { b0 14 [2] c4 0c [2] 83 0e [2] c4 1f [2] 8a 13 [2] 86 19 [2] 91 12 [2] 8a 5c [2] b7 }

  condition:
    any of them
}