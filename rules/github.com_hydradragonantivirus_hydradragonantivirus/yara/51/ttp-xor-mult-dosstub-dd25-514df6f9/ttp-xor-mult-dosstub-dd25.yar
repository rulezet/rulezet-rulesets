rule TTP_XOR_MULT_DOSStub_dd25 {
  strings:
    $key_dd25 = { 89 4d [2] fd 55 [2] ba 57 [2] fd 46 [2] b3 4a [2] bf 40 [2] a8 4b [2] b3 05 [2] 8e }

  condition:
    any of them
}