rule TTP_XOR_MULT_DOSStub_dfe9 {
  strings:
    $key_dfe9 = { 8b 81 [2] ff 99 [2] b8 9b [2] ff 8a [2] b1 86 [2] bd 8c [2] aa 87 [2] b1 c9 [2] 8c }

  condition:
    any of them
}