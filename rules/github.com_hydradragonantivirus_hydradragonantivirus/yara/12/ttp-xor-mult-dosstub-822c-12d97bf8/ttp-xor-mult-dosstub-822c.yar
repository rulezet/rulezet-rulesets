rule TTP_XOR_MULT_DOSStub_822c {
  strings:
    $key_822c = { d6 44 [2] a2 5c [2] e5 5e [2] a2 4f [2] ec 43 [2] e0 49 [2] f7 42 [2] ec 0c [2] d1 }

  condition:
    any of them
}