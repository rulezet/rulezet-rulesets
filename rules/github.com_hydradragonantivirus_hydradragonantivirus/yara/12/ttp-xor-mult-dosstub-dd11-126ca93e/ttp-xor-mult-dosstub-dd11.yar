rule TTP_XOR_MULT_DOSStub_dd11 {
  strings:
    $key_dd11 = { 89 79 [2] fd 61 [2] ba 63 [2] fd 72 [2] b3 7e [2] bf 74 [2] a8 7f [2] b3 31 [2] 8e }

  condition:
    any of them
}