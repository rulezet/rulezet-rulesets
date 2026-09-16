rule TTP_XOR_MULT_DOSStub_e569 {
  strings:
    $key_e569 = { b1 01 [2] c5 19 [2] 82 1b [2] c5 0a [2] 8b 06 [2] 87 0c [2] 90 07 [2] 8b 49 [2] b6 }

  condition:
    any of them
}