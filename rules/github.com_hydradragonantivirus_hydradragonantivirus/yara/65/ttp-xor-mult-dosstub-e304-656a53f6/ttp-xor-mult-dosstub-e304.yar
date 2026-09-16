rule TTP_XOR_MULT_DOSStub_e304 {
  strings:
    $key_e304 = { b7 6c [2] c3 74 [2] 84 76 [2] c3 67 [2] 8d 6b [2] 81 61 [2] 96 6a [2] 8d 24 [2] b0 }

  condition:
    any of them
}