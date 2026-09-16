rule TTP_XOR_MULT_DOSStub_dff6 {
  strings:
    $key_dff6 = { 8b 9e [2] ff 86 [2] b8 84 [2] ff 95 [2] b1 99 [2] bd 93 [2] aa 98 [2] b1 d6 [2] 8c }

  condition:
    any of them
}