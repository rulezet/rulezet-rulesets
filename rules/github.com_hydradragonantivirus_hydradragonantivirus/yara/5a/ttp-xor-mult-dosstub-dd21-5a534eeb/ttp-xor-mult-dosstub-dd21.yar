rule TTP_XOR_MULT_DOSStub_dd21 {
  strings:
    $key_dd21 = { 89 49 [2] fd 51 [2] ba 53 [2] fd 42 [2] b3 4e [2] bf 44 [2] a8 4f [2] b3 01 [2] 8e }

  condition:
    any of them
}