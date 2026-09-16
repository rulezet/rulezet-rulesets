rule TTP_XOR_MULT_DOSStub_c55c {
  strings:
    $key_c55c = { 91 34 [2] e5 2c [2] a2 2e [2] e5 3f [2] ab 33 [2] a7 39 [2] b0 32 [2] ab 7c [2] 96 }

  condition:
    any of them
}