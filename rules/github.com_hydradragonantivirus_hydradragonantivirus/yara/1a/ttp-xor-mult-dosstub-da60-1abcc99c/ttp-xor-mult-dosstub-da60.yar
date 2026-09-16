rule TTP_XOR_MULT_DOSStub_da60 {
  strings:
    $key_da60 = { 8e 08 [2] fa 10 [2] bd 12 [2] fa 03 [2] b4 0f [2] b8 05 [2] af 0e [2] b4 40 [2] 89 }

  condition:
    any of them
}