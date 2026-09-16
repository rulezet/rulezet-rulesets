rule TTP_XOR_MULT_DOSStub_dfe2 {
  strings:
    $key_dfe2 = { 8b 8a [2] ff 92 [2] b8 90 [2] ff 81 [2] b1 8d [2] bd 87 [2] aa 8c [2] b1 c2 [2] 8c }

  condition:
    any of them
}