rule TTP_XOR_MULT_DOSStub_da32 {
  strings:
    $key_da32 = { 8e 5a [2] fa 42 [2] bd 40 [2] fa 51 [2] b4 5d [2] b8 57 [2] af 5c [2] b4 12 [2] 89 }

  condition:
    any of them
}