rule TTP_XOR_MULT_DOSStub_e178 {
  strings:
    $key_e178 = { b5 10 [2] c1 08 [2] 86 0a [2] c1 1b [2] 8f 17 [2] 83 1d [2] 94 16 [2] 8f 58 [2] b2 }

  condition:
    any of them
}