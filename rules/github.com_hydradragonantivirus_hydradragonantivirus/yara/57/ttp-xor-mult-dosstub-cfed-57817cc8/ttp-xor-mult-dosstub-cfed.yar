rule TTP_XOR_MULT_DOSStub_cfed {
  strings:
    $key_cfed = { 9b 85 [2] ef 9d [2] a8 9f [2] ef 8e [2] a1 82 [2] ad 88 [2] ba 83 [2] a1 cd [2] 9c }

  condition:
    any of them
}