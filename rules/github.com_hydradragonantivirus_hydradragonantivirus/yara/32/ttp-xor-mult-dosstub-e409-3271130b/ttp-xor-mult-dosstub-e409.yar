rule TTP_XOR_MULT_DOSStub_e409 {
  strings:
    $key_e409 = { b0 61 [2] c4 79 [2] 83 7b [2] c4 6a [2] 8a 66 [2] 86 6c [2] 91 67 [2] 8a 29 [2] b7 }

  condition:
    any of them
}