rule TTP_XOR_MULT_DOSStub_e164 {
  strings:
    $key_e164 = { b5 0c [2] c1 14 [2] 86 16 [2] c1 07 [2] 8f 0b [2] 83 01 [2] 94 0a [2] 8f 44 [2] b2 }

  condition:
    any of them
}