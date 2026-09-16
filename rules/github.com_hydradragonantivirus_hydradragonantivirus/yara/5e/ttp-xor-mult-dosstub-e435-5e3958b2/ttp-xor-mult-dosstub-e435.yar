rule TTP_XOR_MULT_DOSStub_e435 {
  strings:
    $key_e435 = { b0 5d [2] c4 45 [2] 83 47 [2] c4 56 [2] 8a 5a [2] 86 50 [2] 91 5b [2] 8a 15 [2] b7 }

  condition:
    any of them
}