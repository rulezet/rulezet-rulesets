rule TTP_XOR_MULT_DOSStub_c8d5 {
  strings:
    $key_c8d5 = { 9c bd [2] e8 a5 [2] af a7 [2] e8 b6 [2] a6 ba [2] aa b0 [2] bd bb [2] a6 f5 [2] 9b }

  condition:
    any of them
}