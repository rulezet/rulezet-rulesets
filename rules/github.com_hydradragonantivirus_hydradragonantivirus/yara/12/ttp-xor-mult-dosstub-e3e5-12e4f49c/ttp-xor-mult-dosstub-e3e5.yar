rule TTP_XOR_MULT_DOSStub_e3e5 {
  strings:
    $key_e3e5 = { b7 8d [2] c3 95 [2] 84 97 [2] c3 86 [2] 8d 8a [2] 81 80 [2] 96 8b [2] 8d c5 [2] b0 }

  condition:
    any of them
}