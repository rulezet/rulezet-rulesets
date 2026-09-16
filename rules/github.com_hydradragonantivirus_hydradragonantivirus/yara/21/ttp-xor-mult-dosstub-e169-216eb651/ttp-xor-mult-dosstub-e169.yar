rule TTP_XOR_MULT_DOSStub_e169 {
  strings:
    $key_e169 = { b5 01 [2] c1 19 [2] 86 1b [2] c1 0a [2] 8f 06 [2] 83 0c [2] 94 07 [2] 8f 49 [2] b2 }

  condition:
    any of them
}