rule TTP_XOR_MULT_DOSStub_da00 {
  strings:
    $key_da00 = { 8e 68 [2] fa 70 [2] bd 72 [2] fa 63 [2] b4 6f [2] b8 65 [2] af 6e [2] b4 20 [2] 89 }

  condition:
    any of them
}