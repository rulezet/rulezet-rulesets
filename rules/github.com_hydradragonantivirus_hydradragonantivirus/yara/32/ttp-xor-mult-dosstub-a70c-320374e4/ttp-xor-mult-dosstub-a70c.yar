rule TTP_XOR_MULT_DOSStub_a70c {
  strings:
    $key_a70c = { f3 64 [2] 87 7c [2] c0 7e [2] 87 6f [2] c9 63 [2] c5 69 [2] d2 62 [2] c9 2c [2] f4 }

  condition:
    any of them
}