rule TTP_XOR_MULT_DOSStub_832b {
  strings:
    $key_832b = { d7 43 [2] a3 5b [2] e4 59 [2] a3 48 [2] ed 44 [2] e1 4e [2] f6 45 [2] ed 0b [2] d0 }

  condition:
    any of them
}