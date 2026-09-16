rule TTP_XOR_MULT_DOSStub_ca24 {
  strings:
    $key_ca24 = { 9e 4c [2] ea 54 [2] ad 56 [2] ea 47 [2] a4 4b [2] a8 41 [2] bf 4a [2] a4 04 [2] 99 }

  condition:
    any of them
}