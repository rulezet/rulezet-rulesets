rule TTP_XOR_MULT_DOSStub_da1b {
  strings:
    $key_da1b = { 8e 73 [2] fa 6b [2] bd 69 [2] fa 78 [2] b4 74 [2] b8 7e [2] af 75 [2] b4 3b [2] 89 }

  condition:
    any of them
}