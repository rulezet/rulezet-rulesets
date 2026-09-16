rule TTP_XOR_MULT_DOSStub_e124 {
  strings:
    $key_e124 = { b5 4c [2] c1 54 [2] 86 56 [2] c1 47 [2] 8f 4b [2] 83 41 [2] 94 4a [2] 8f 04 [2] b2 }

  condition:
    any of them
}