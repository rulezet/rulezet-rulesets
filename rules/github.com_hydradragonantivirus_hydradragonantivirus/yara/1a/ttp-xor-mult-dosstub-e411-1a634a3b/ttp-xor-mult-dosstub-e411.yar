rule TTP_XOR_MULT_DOSStub_e411 {
  strings:
    $key_e411 = { b0 79 [2] c4 61 [2] 83 63 [2] c4 72 [2] 8a 7e [2] 86 74 [2] 91 7f [2] 8a 31 [2] b7 }

  condition:
    any of them
}