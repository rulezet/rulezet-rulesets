rule TTP_XOR_MULT_DOSStub_dfae {
  strings:
    $key_dfae = { 8b c6 [2] ff de [2] b8 dc [2] ff cd [2] b1 c1 [2] bd cb [2] aa c0 [2] b1 8e [2] 8c }

  condition:
    any of them
}