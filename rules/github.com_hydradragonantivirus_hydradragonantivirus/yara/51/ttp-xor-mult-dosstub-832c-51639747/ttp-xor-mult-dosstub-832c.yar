rule TTP_XOR_MULT_DOSStub_832c {
  strings:
    $key_832c = { d7 44 [2] a3 5c [2] e4 5e [2] a3 4f [2] ed 43 [2] e1 49 [2] f6 42 [2] ed 0c [2] d0 }

  condition:
    any of them
}