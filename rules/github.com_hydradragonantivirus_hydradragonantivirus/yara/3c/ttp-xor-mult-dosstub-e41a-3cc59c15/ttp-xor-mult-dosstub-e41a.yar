rule TTP_XOR_MULT_DOSStub_e41a {
  strings:
    $key_e41a = { b0 72 [2] c4 6a [2] 83 68 [2] c4 79 [2] 8a 75 [2] 86 7f [2] 91 74 [2] 8a 3a [2] b7 }

  condition:
    any of them
}