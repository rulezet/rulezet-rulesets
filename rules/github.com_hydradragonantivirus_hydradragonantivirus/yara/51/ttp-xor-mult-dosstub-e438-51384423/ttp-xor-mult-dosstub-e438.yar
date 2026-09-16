rule TTP_XOR_MULT_DOSStub_e438 {
  strings:
    $key_e438 = { b0 50 [2] c4 48 [2] 83 4a [2] c4 5b [2] 8a 57 [2] 86 5d [2] 91 56 [2] 8a 18 [2] b7 }

  condition:
    any of them
}