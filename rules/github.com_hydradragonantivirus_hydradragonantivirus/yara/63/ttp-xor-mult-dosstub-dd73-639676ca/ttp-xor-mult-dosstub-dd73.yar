rule TTP_XOR_MULT_DOSStub_dd73 {
  strings:
    $key_dd73 = { 89 1b [2] fd 03 [2] ba 01 [2] fd 10 [2] b3 1c [2] bf 16 [2] a8 1d [2] b3 53 [2] 8e }

  condition:
    any of them
}