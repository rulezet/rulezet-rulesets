rule TTP_XOR_MULT_DOSStub_da3b {
  strings:
    $key_da3b = { 8e 53 [2] fa 4b [2] bd 49 [2] fa 58 [2] b4 54 [2] b8 5e [2] af 55 [2] b4 1b [2] 89 }

  condition:
    any of them
}