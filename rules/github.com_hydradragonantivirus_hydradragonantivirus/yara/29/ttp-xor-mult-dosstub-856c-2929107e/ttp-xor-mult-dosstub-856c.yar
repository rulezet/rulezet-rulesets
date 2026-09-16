rule TTP_XOR_MULT_DOSStub_856c {
  strings:
    $key_856c = { d1 04 [2] a5 1c [2] e2 1e [2] a5 0f [2] eb 03 [2] e7 09 [2] f0 02 [2] eb 4c [2] d6 }

  condition:
    any of them
}