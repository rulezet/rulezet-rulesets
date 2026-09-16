rule TTP_XOR_MULT_DOSStub_e064 {
  strings:
    $key_e064 = { b4 0c [2] c0 14 [2] 87 16 [2] c0 07 [2] 8e 0b [2] 82 01 [2] 95 0a [2] 8e 44 [2] b3 }

  condition:
    any of them
}