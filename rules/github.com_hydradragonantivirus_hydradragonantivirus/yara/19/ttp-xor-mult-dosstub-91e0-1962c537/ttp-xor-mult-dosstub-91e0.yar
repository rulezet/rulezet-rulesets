rule TTP_XOR_MULT_DOSStub_91e0 {
  strings:
    $key_91e0 = { c5 88 [2] b1 90 [2] f6 92 [2] b1 83 [2] ff 8f [2] f3 85 [2] e4 8e [2] ff c0 [2] c2 }

  condition:
    any of them
}