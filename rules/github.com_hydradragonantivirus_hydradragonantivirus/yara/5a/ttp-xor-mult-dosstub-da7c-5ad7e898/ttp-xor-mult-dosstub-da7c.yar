rule TTP_XOR_MULT_DOSStub_da7c {
  strings:
    $key_da7c = { 8e 14 [2] fa 0c [2] bd 0e [2] fa 1f [2] b4 13 [2] b8 19 [2] af 12 [2] b4 5c [2] 89 }

  condition:
    any of them
}