rule TTP_XOR_MULT_DOSStub_e4e3 {
  strings:
    $key_e4e3 = { b0 8b [2] c4 93 [2] 83 91 [2] c4 80 [2] 8a 8c [2] 86 86 [2] 91 8d [2] 8a c3 [2] b7 }

  condition:
    any of them
}