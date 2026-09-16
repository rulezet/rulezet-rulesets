rule TTP_XOR_MULT_DOSStub_dfda {
  strings:
    $key_dfda = { 8b b2 [2] ff aa [2] b8 a8 [2] ff b9 [2] b1 b5 [2] bd bf [2] aa b4 [2] b1 fa [2] 8c }

  condition:
    any of them
}