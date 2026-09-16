rule TTP_XOR_MULT_DOSStub_e524 {
  strings:
    $key_e524 = { b1 4c [2] c5 54 [2] 82 56 [2] c5 47 [2] 8b 4b [2] 87 41 [2] 90 4a [2] 8b 04 [2] b6 }

  condition:
    any of them
}