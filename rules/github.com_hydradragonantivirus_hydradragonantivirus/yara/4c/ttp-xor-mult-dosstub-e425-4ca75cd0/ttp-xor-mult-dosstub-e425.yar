rule TTP_XOR_MULT_DOSStub_e425 {
  strings:
    $key_e425 = { b0 4d [2] c4 55 [2] 83 57 [2] c4 46 [2] 8a 4a [2] 86 40 [2] 91 4b [2] 8a 05 [2] b7 }

  condition:
    any of them
}