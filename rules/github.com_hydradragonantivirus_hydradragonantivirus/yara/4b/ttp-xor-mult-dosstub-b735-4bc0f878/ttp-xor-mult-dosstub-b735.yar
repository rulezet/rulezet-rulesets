rule TTP_XOR_MULT_DOSStub_b735 {
  strings:
    $key_b735 = { e3 5d [2] 97 45 [2] d0 47 [2] 97 56 [2] d9 5a [2] d5 50 [2] c2 5b [2] d9 15 [2] e4 }

  condition:
    any of them
}