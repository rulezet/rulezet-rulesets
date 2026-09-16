rule TTP_XOR_MULT_DOSStub_dded {
  strings:
    $key_dded = { 89 85 [2] fd 9d [2] ba 9f [2] fd 8e [2] b3 82 [2] bf 88 [2] a8 83 [2] b3 cd [2] 8e }

  condition:
    any of them
}