rule TTP_XOR_MULT_DOSStub_e402 {
  strings:
    $key_e402 = { b0 6a [2] c4 72 [2] 83 70 [2] c4 61 [2] 8a 6d [2] 86 67 [2] 91 6c [2] 8a 22 [2] b7 }

  condition:
    any of them
}