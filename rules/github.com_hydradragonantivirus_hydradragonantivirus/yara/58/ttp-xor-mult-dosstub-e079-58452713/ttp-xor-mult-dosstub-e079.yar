rule TTP_XOR_MULT_DOSStub_e079 {
  strings:
    $key_e079 = { b4 11 [2] c0 09 [2] 87 0b [2] c0 1a [2] 8e 16 [2] 82 1c [2] 95 17 [2] 8e 59 [2] b3 }

  condition:
    any of them
}