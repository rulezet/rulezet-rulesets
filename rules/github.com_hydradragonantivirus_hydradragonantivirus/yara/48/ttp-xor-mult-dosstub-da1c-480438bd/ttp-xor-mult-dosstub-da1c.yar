rule TTP_XOR_MULT_DOSStub_da1c {
  strings:
    $key_da1c = { 8e 74 [2] fa 6c [2] bd 6e [2] fa 7f [2] b4 73 [2] b8 79 [2] af 72 [2] b4 3c [2] 89 }

  condition:
    any of them
}