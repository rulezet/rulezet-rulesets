rule TTP_XOR_MULT_DOSStub_8573 {
  strings:
    $key_8573 = { d1 1b [2] a5 03 [2] e2 01 [2] a5 10 [2] eb 1c [2] e7 16 [2] f0 1d [2] eb 53 [2] d6 }

  condition:
    any of them
}