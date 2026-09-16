rule TTP_XOR_MULT_DOSStub_e533 {
  strings:
    $key_e533 = { b1 5b [2] c5 43 [2] 82 41 [2] c5 50 [2] 8b 5c [2] 87 56 [2] 90 5d [2] 8b 13 [2] b6 }

  condition:
    any of them
}