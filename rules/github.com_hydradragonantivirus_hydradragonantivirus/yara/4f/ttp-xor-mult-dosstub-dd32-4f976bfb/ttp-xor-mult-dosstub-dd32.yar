rule TTP_XOR_MULT_DOSStub_dd32 {
  strings:
    $key_dd32 = { 89 5a [2] fd 42 [2] ba 40 [2] fd 51 [2] b3 5d [2] bf 57 [2] a8 5c [2] b3 12 [2] 8e }

  condition:
    any of them
}