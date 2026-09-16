rule TTP_XOR_MULT_DOSStub_876c {
  strings:
    $key_876c = { d3 04 [2] a7 1c [2] e0 1e [2] a7 0f [2] e9 03 [2] e5 09 [2] f2 02 [2] e9 4c [2] d4 }

  condition:
    any of them
}