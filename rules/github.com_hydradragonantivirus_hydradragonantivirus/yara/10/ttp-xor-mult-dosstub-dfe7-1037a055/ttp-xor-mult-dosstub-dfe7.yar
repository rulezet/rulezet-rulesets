rule TTP_XOR_MULT_DOSStub_dfe7 {
  strings:
    $key_dfe7 = { 8b 8f [2] ff 97 [2] b8 95 [2] ff 84 [2] b1 88 [2] bd 82 [2] aa 89 [2] b1 c7 [2] 8c }

  condition:
    any of them
}