rule TTP_XOR_MULT_DOSStub_dd19 {
  strings:
    $key_dd19 = { 89 71 [2] fd 69 [2] ba 6b [2] fd 7a [2] b3 76 [2] bf 7c [2] a8 77 [2] b3 39 [2] 8e }

  condition:
    any of them
}