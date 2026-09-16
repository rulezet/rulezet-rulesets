rule TTP_XOR_MULT_DOSStub_833c {
  strings:
    $key_833c = { d7 54 [2] a3 4c [2] e4 4e [2] a3 5f [2] ed 53 [2] e1 59 [2] f6 52 [2] ed 1c [2] d0 }

  condition:
    any of them
}