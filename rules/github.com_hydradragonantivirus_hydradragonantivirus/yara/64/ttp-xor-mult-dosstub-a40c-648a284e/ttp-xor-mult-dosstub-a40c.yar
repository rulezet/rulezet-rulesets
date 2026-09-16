rule TTP_XOR_MULT_DOSStub_a40c {
  strings:
    $key_a40c = { f0 64 [2] 84 7c [2] c3 7e [2] 84 6f [2] ca 63 [2] c6 69 [2] d1 62 [2] ca 2c [2] f7 }

  condition:
    any of them
}