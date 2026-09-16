rule TTP_XOR_MULT_DOSStub_fa91 {
  strings:
    $key_fa91 = { ae f9 [2] da e1 [2] 9d e3 [2] da f2 [2] 94 fe [2] 98 f4 [2] 8f ff [2] 94 b1 [2] a9 }

  condition:
    any of them
}