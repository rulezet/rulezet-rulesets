rule TTP_XOR_MULT_DOSStub_da01 {
  strings:
    $key_da01 = { 8e 69 [2] fa 71 [2] bd 73 [2] fa 62 [2] b4 6e [2] b8 64 [2] af 6f [2] b4 21 [2] 89 }

  condition:
    any of them
}