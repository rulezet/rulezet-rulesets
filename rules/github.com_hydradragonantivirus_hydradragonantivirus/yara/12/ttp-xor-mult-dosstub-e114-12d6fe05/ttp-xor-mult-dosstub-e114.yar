rule TTP_XOR_MULT_DOSStub_e114 {
  strings:
    $key_e114 = { b5 7c [2] c1 64 [2] 86 66 [2] c1 77 [2] 8f 7b [2] 83 71 [2] 94 7a [2] 8f 34 [2] b2 }

  condition:
    any of them
}