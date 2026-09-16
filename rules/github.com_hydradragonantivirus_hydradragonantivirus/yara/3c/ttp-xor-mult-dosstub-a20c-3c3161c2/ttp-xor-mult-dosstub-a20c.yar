rule TTP_XOR_MULT_DOSStub_a20c {
  strings:
    $key_a20c = { f6 64 [2] 82 7c [2] c5 7e [2] 82 6f [2] cc 63 [2] c0 69 [2] d7 62 [2] cc 2c [2] f1 }

  condition:
    any of them
}