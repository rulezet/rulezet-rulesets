rule TTP_XOR_MULT_DOSStub_e47a {
  strings:
    $key_e47a = { b0 12 [2] c4 0a [2] 83 08 [2] c4 19 [2] 8a 15 [2] 86 1f [2] 91 14 [2] 8a 5a [2] b7 }

  condition:
    any of them
}