rule TTP_XOR_MULT_DOSStub_e529 {
  strings:
    $key_e529 = { b1 41 [2] c5 59 [2] 82 5b [2] c5 4a [2] 8b 46 [2] 87 4c [2] 90 47 [2] 8b 09 [2] b6 }

  condition:
    any of them
}