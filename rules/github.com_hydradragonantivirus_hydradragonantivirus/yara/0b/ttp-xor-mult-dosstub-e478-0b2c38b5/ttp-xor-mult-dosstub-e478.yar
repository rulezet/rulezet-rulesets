rule TTP_XOR_MULT_DOSStub_e478 {
  strings:
    $key_e478 = { b0 10 [2] c4 08 [2] 83 0a [2] c4 1b [2] 8a 17 [2] 86 1d [2] 91 16 [2] 8a 58 [2] b7 }

  condition:
    any of them
}