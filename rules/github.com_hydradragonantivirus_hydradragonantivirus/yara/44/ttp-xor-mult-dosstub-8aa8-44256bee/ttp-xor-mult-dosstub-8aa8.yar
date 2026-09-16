rule TTP_XOR_MULT_DOSStub_8aa8 {
  strings:
    $key_8aa8 = { de c0 [2] aa d8 [2] ed da [2] aa cb [2] e4 c7 [2] e8 cd [2] ff c6 [2] e4 88 [2] d9 }

  condition:
    any of them
}