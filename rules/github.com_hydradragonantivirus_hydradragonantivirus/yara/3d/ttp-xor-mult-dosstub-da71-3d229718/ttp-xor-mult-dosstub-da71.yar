rule TTP_XOR_MULT_DOSStub_da71 {
  strings:
    $key_da71 = { 8e 19 [2] fa 01 [2] bd 03 [2] fa 12 [2] b4 1e [2] b8 14 [2] af 1f [2] b4 51 [2] 89 }

  condition:
    any of them
}