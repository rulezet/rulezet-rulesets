rule TTP_XOR_MULT_DOSStub_e624 {
  strings:
    $key_e624 = { b2 4c [2] c6 54 [2] 81 56 [2] c6 47 [2] 88 4b [2] 84 41 [2] 93 4a [2] 88 04 [2] b5 }

  condition:
    any of them
}