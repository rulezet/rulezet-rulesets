rule TTP_XOR_MULT_DOSStub_e428 {
  strings:
    $key_e428 = { b0 40 [2] c4 58 [2] 83 5a [2] c4 4b [2] 8a 47 [2] 86 4d [2] 91 46 [2] 8a 08 [2] b7 }

  condition:
    any of them
}