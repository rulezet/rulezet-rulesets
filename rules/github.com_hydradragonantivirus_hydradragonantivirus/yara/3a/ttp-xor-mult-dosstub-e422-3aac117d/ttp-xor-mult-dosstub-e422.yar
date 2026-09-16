rule TTP_XOR_MULT_DOSStub_e422 {
  strings:
    $key_e422 = { b0 4a [2] c4 52 [2] 83 50 [2] c4 41 [2] 8a 4d [2] 86 47 [2] 91 4c [2] 8a 02 [2] b7 }

  condition:
    any of them
}