rule TTP_XOR_MULT_DOSStub_dd24 {
  strings:
    $key_dd24 = { 89 4c [2] fd 54 [2] ba 56 [2] fd 47 [2] b3 4b [2] bf 41 [2] a8 4a [2] b3 04 [2] 8e }

  condition:
    any of them
}