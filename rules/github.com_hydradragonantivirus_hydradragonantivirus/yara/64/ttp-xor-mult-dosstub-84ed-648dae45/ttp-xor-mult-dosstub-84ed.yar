rule TTP_XOR_MULT_DOSStub_84ed {
  strings:
    $key_84ed = { d0 85 [2] a4 9d [2] e3 9f [2] a4 8e [2] ea 82 [2] e6 88 [2] f1 83 [2] ea cd [2] d7 }

  condition:
    any of them
}