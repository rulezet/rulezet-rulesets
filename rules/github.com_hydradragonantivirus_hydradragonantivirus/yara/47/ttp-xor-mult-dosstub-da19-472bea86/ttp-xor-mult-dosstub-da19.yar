rule TTP_XOR_MULT_DOSStub_da19 {
  strings:
    $key_da19 = { 8e 71 [2] fa 69 [2] bd 6b [2] fa 7a [2] b4 76 [2] b8 7c [2] af 77 [2] b4 39 [2] 89 }

  condition:
    any of them
}