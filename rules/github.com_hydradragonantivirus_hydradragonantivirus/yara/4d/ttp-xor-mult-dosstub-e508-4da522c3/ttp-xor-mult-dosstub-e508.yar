rule TTP_XOR_MULT_DOSStub_e508 {
  strings:
    $key_e508 = { b1 60 [2] c5 78 [2] 82 7a [2] c5 6b [2] 8b 67 [2] 87 6d [2] 90 66 [2] 8b 28 [2] b6 }

  condition:
    any of them
}