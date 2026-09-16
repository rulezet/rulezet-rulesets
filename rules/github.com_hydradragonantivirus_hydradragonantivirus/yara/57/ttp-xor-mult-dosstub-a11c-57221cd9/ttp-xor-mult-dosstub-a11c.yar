rule TTP_XOR_MULT_DOSStub_a11c {
  strings:
    $key_a11c = { f5 74 [2] 81 6c [2] c6 6e [2] 81 7f [2] cf 73 [2] c3 79 [2] d4 72 [2] cf 3c [2] f2 }

  condition:
    any of them
}