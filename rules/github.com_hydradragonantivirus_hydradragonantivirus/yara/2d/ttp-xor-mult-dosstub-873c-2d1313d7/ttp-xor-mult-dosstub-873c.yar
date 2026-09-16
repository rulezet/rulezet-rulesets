rule TTP_XOR_MULT_DOSStub_873c {
  strings:
    $key_873c = { d3 54 [2] a7 4c [2] e0 4e [2] a7 5f [2] e9 53 [2] e5 59 [2] f2 52 [2] e9 1c [2] d4 }

  condition:
    any of them
}