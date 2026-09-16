rule TTP_XOR_MULT_DOSStub_dd1c {
  strings:
    $key_dd1c = { 89 74 [2] fd 6c [2] ba 6e [2] fd 7f [2] b3 73 [2] bf 79 [2] a8 72 [2] b3 3c [2] 8e }

  condition:
    any of them
}