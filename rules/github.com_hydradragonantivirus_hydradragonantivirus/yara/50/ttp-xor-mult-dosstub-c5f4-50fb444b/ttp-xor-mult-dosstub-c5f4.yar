rule TTP_XOR_MULT_DOSStub_c5f4 {
  strings:
    $key_c5f4 = { 91 9c [2] e5 84 [2] a2 86 [2] e5 97 [2] ab 9b [2] a7 91 [2] b0 9a [2] ab d4 [2] 96 }

  condition:
    any of them
}