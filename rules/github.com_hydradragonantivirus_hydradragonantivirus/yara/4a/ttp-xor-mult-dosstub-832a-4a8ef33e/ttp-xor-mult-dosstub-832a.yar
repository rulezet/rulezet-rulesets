rule TTP_XOR_MULT_DOSStub_832a {
  strings:
    $key_832a = { d7 42 [2] a3 5a [2] e4 58 [2] a3 49 [2] ed 45 [2] e1 4f [2] f6 44 [2] ed 0a [2] d0 }

  condition:
    any of them
}