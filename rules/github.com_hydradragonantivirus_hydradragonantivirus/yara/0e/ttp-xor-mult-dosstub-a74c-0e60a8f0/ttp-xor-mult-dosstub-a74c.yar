rule TTP_XOR_MULT_DOSStub_a74c {
  strings:
    $key_a74c = { f3 24 [2] 87 3c [2] c0 3e [2] 87 2f [2] c9 23 [2] c5 29 [2] d2 22 [2] c9 6c [2] f4 }

  condition:
    any of them
}