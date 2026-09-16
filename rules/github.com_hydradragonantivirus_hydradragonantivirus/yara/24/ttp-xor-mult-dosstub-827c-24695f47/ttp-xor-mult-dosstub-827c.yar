rule TTP_XOR_MULT_DOSStub_827c {
  strings:
    $key_827c = { d6 14 [2] a2 0c [2] e5 0e [2] a2 1f [2] ec 13 [2] e0 19 [2] f7 12 [2] ec 5c [2] d1 }

  condition:
    any of them
}