rule TTP_XOR_MULT_DOSStub_dff4 {
  strings:
    $key_dff4 = { 8b 9c [2] ff 84 [2] b8 86 [2] ff 97 [2] b1 9b [2] bd 91 [2] aa 9a [2] b1 d4 [2] 8c }

  condition:
    any of them
}