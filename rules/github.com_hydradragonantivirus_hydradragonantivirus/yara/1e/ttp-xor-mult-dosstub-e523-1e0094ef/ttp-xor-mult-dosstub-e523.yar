rule TTP_XOR_MULT_DOSStub_e523 {
  strings:
    $key_e523 = { b1 4b [2] c5 53 [2] 82 51 [2] c5 40 [2] 8b 4c [2] 87 46 [2] 90 4d [2] 8b 03 [2] b6 }

  condition:
    any of them
}