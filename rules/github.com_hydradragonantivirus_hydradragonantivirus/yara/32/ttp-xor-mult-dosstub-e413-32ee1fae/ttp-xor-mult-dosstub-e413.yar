rule TTP_XOR_MULT_DOSStub_e413 {
  strings:
    $key_e413 = { b0 7b [2] c4 63 [2] 83 61 [2] c4 70 [2] 8a 7c [2] 86 76 [2] 91 7d [2] 8a 33 [2] b7 }

  condition:
    any of them
}