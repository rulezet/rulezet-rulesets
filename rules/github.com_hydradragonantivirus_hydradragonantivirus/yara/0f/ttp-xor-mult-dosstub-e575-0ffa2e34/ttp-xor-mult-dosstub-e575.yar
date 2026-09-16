rule TTP_XOR_MULT_DOSStub_e575 {
  strings:
    $key_e575 = { b1 1d [2] c5 05 [2] 82 07 [2] c5 16 [2] 8b 1a [2] 87 10 [2] 90 1b [2] 8b 55 [2] b6 }

  condition:
    any of them
}