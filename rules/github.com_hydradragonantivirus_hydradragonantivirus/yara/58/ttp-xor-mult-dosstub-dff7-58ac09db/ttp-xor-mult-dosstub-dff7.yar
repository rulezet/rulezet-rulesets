rule TTP_XOR_MULT_DOSStub_dff7 {
  strings:
    $key_dff7 = { 8b 9f [2] ff 87 [2] b8 85 [2] ff 94 [2] b1 98 [2] bd 92 [2] aa 99 [2] b1 d7 [2] 8c }

  condition:
    any of them
}