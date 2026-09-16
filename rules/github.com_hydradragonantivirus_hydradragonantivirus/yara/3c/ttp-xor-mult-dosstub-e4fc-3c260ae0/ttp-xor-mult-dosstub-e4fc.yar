rule TTP_XOR_MULT_DOSStub_e4fc {
  strings:
    $key_e4fc = { b0 94 [2] c4 8c [2] 83 8e [2] c4 9f [2] 8a 93 [2] 86 99 [2] 91 92 [2] 8a dc [2] b7 }

  condition:
    any of them
}