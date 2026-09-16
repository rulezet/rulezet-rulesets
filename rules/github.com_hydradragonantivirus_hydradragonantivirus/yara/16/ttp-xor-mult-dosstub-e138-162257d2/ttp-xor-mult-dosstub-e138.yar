rule TTP_XOR_MULT_DOSStub_e138 {
  strings:
    $key_e138 = { b5 50 [2] c1 48 [2] 86 4a [2] c1 5b [2] 8f 57 [2] 83 5d [2] 94 56 [2] 8f 18 [2] b2 }

  condition:
    any of them
}