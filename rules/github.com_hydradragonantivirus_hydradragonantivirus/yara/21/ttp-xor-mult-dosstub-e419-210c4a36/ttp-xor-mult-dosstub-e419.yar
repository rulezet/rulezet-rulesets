rule TTP_XOR_MULT_DOSStub_e419 {
  strings:
    $key_e419 = { b0 71 [2] c4 69 [2] 83 6b [2] c4 7a [2] 8a 76 [2] 86 7c [2] 91 77 [2] 8a 39 [2] b7 }

  condition:
    any of them
}